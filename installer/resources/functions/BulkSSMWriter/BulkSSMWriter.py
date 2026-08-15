# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Bulk SSM Parameter Writer -- CloudFormation Custom Resource.

Reads a JSON payload (param_name -> param_value map) from S3 and writes
the parameters to SSM Parameter Store in a single CFN Custom Resource
invocation. This collapses hundreds of AWS::SSM::Parameter CFN resources
into a single CustomResource, staying well under the 500-resource stack
limit and avoiding CFN property size limits by sourcing the payload from
S3 rather than inline CFN properties.

Two-channel input (Option 3 split):
    * Synth-time-known params (static config, large pile) arrive via S3.
    * Deploy-time-resolved params that contain CDK tokens (VPC ids, ARNs,
      subnet lists, etc.) arrive inline via CustomResource properties.
      CloudFormation resolves these tokens before calling the Lambda so
      the values are concrete by the time we read them.

Both sets are merged (resolved_params wins on key collisions) and written
in a single pass.

ResourceProperties (set by CDK):
    s3_bucket         -- S3 bucket containing the payload JSON (optional
                         if resolved_params is provided)
    s3_key            -- S3 key of the payload JSON (optional if
                         resolved_params is provided)
    content_hash      -- SHA256 hex of the payload; forces CFN Update
                         when the parameter set changes
    resolved_params   -- (optional) dict of name -> value for params
                         whose values are only known at deploy time

Resilience:
    * boto3 'standard' retry mode (10 attempts) handles SSM throttles
      (ThrottlingException, TooManyUpdatesException) silently.
    * Outer retry loop (5 attempts, exp backoff 5/10/20/40/80s) catches
      AccessDeniedException (IAM propagation race) and any throttle
      residue that escapes boto3.
    * Per-parameter failures are accumulated in a list rather than
      aborting on first error; a run summary is logged before return.

Observability:
    Every invocation emits a single 'BulkSSMWriter run summary' INFO log
    line on exit (success or failure) with fields:
        request_type, outcome, detail, content_hash, total_params,
        processed, failures (count), errors_by_type, elapsed_s,
        s3://..., failure_sample.
    ``errors_by_type`` is a dict of ``{exception_type: count}`` sorted
    descending by count; it includes every exception observed during
    the run, including transient retries that eventually succeeded, so
    operators see the true rate of API friction.
    The CFN Custom Resource response Data also includes 'Failures'
    (count) so callers can correlate without reading the log group.
"""

import json
import logging
import time

import boto3
from botocore.config import Config
import cfnresponse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# boto3 adaptive retry mode (replaces standard mode as of this
# change). Adaptive mode layers a client-side rate limiter on top of
# the standard full-jitter backoff: when it detects throttling, it
# preemptively slows subsequent requests to stay under the
# service-side cap, rather than letting every call hit a
# ThrottlingException and burn backoff. Combined with the outer loop
# below, this bounds total tail latency for sustained throttle
# storms (e.g. a noisy neighbor consuming the account's SSM budget).
#
# max_attempts=20 (up from standard's 10) gives the rate limiter room
# to adapt before we escalate to the outer loop.
_BOTO_RETRY_CONFIG = Config(
    retries={"max_attempts": 20, "mode": "adaptive"},
)

ssm = boto3.client("ssm", config=_BOTO_RETRY_CONFIG)
s3 = boto3.client("s3", config=_BOTO_RETRY_CONFIG)

# SSM DeleteParameters accepts up to 10 names per call.
DELETE_BATCH_SIZE = 10

# IAM policy propagation can lag several seconds behind role creation.
# Since this Custom Resource may fire immediately after the Lambda's
# inline policy is attached, we retry AccessDeniedException (and any
# throttle that escapes the boto3 built-in retries) with exponential
# backoff to let the policy propagate before failing.
MAX_RETRIES = 5
RETRY_BASE_DELAY = 5  # seconds: 5, 10, 20, 40, 80 => ~155s max

# Per-parameter throttle budget. When sustained throttling would push
# the outer retry loop past this wall-clock limit, we mark the param
# with ``ThrottleExhausted`` in error_stats and re-raise, rather than
# continuing to burn the Lambda's 15 minute execution budget on a
# single doomed param. The goal is to fail fast on unrecoverable
# throttling so the stack rollback kicks in while operator time is
# still meaningful -- and so one stuck param can't starve the rest.
# 120 s is chosen as the smallest value that still tolerates a typical
# SSM throttle recovery window (tens of seconds) without leaving
# genuine multi-minute outages masked.
PER_PARAM_THROTTLE_BUDGET_SECONDS = 120

# Error codes that indicate SSM-side throttling. When we retry these
# and the per-param wall-clock budget is exceeded, we record the
# terminal failure as ThrottleExhausted (distinct from, e.g., a final
# AccessDeniedException) so operators can distinguish throttle-storm
# failures from IAM / validation failures in the run summary.
_THROTTLE_ERROR_CODES = (
    "ThrottlingException",
    "TooManyUpdatesException",
    "RequestLimitExceeded",
    "ProvisionedThroughputExceededException",
)

# Exception substrings we consider retryable at the outer loop level.
# boto3 adaptive retry mode handles most of these silently; this list
# is the safety net for bursts that exhaust boto3's retry budget or
# for the first-invocation IAM propagation race.
_RETRYABLE_ERROR_CODES = (
    "AccessDeniedException",
) + _THROTTLE_ERROR_CODES


def _is_retryable(exc: Exception) -> bool:
    msg = str(exc)
    return any(code in msg for code in _RETRYABLE_ERROR_CODES)


def _is_throttle(exc: Exception) -> bool:
    """True if exc is a SSM-side throttle/rate-limit exception."""
    msg = str(exc)
    return any(code in msg for code in _THROTTLE_ERROR_CODES)


def _backoff(attempt: int) -> None:
    """Sleep for exponential backoff. attempt is 0-indexed."""
    delay = RETRY_BASE_DELAY * (2 ** attempt)
    time.sleep(delay)


def _record_error(stats: dict, exc: Exception) -> None:
    """
    Increment the per-exception-type counter for an observed exception.

    Botocore exceptions of class ``ClientError`` carry their specific
    API error code in ``exc.response["Error"]["Code"]`` (e.g.
    ``ThrottlingException``). We prefer that code over the Python class
    name when available so the stats line up with what an operator
    would see in CloudTrail / SSM API metrics.
    """
    key = type(exc).__name__
    try:
        from botocore.exceptions import ClientError  # local import to avoid cold-start cost
        if isinstance(exc, ClientError):
            code = (exc.response or {}).get("Error", {}).get("Code")
            if code:
                key = code
    except Exception:  # pragma: no cover -- never let stats recording fail
        pass
    stats[key] = stats.get(key, 0) + 1


def load_payload_from_s3(bucket: str, key: str) -> dict:
    """Fetch and parse the JSON parameter payload from S3."""
    logger.info(f"Loading parameter payload from s3://{bucket}/{key}")
    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj["Body"].read()
    params = json.loads(body)
    if not isinstance(params, dict):
        raise ValueError(
            f"Payload must be a JSON object (name -> value); got {type(params).__name__}"
        )
    return params


def put_parameters(params: dict, failures: list, error_stats: dict,
                   tags: list | None = None) -> int:
    """
    Write all parameters to SSM. Retries retryable errors at the outer
    loop for IAM propagation + throttle residue. Per-parameter failures
    are appended to ``failures`` as ``{"name": ..., "error": ...}`` so
    the caller can surface a summary at end of run.

    ``error_stats`` is a dict accumulator keyed by exception class name
    (e.g. ``ThrottlingException``, ``AccessDeniedException``,
    ``ClientError``). Every exception encountered -- even ones that are
    retried and eventually succeed -- increments the counter so the
    final summary reflects the true rate of API friction observed.

    ``tags`` (optional): list of ``{"Key": k, "Value": v}`` applied to
    each parameter via ``ssm:AddTagsToResource`` right after a
    successful put. ``Overwrite=True`` mode rejects Tags= on
    put_parameter itself, so we make a second call. Tag-application
    failures are recorded but never abort the whole run -- having the
    parameter value is more important than having the tags.
    """
    count = 0
    for name, value in params.items():
        _throttle_deadline = time.monotonic() + PER_PARAM_THROTTLE_BUDGET_SECONDS
        for attempt in range(MAX_RETRIES):
            try:
                ssm.put_parameter(
                    Name=name,
                    Value=str(value),
                    Type="String",
                    Overwrite=True,
                    Tier="Standard",
                )
                count += 1
                break
            except ssm.exceptions.ParameterLimitExceeded as e:
                _record_error(error_stats, e)
                logger.error(f"SSM parameter limit exceeded writing {name}: {e}")
                failures.append({"name": name, "error": f"ParameterLimitExceeded: {e}"})
                # Limit exceeded is account-level; no point continuing.
                raise
            except Exception as e:
                _record_error(error_stats, e)

                # Throttle budget check: if this is a throttle-class
                # error and we've exceeded PER_PARAM_THROTTLE_BUDGET_SECONDS
                # of retrying *this* parameter, stop retrying so one
                # stuck param can't starve the rest of the bulk write.
                if _is_throttle(e) and time.monotonic() >= _throttle_deadline:
                    _record_error(error_stats,
                                  type("ThrottleExhausted", (Exception,),
                                       {})(f"{type(e).__name__}: {e}"))
                    logger.error(
                        f"Throttle budget exhausted on {name} after "
                        f"{attempt + 1} attempts "
                        f"({PER_PARAM_THROTTLE_BUDGET_SECONDS}s wall): "
                        f"{type(e).__name__}: {e}"
                    )
                    failures.append({
                        "name": name,
                        "error": f"ThrottleExhausted after "
                                 f"{PER_PARAM_THROTTLE_BUDGET_SECONDS}s: "
                                 f"{type(e).__name__}: {e}",
                        "attempts": attempt + 1,
                    })
                    raise

                if _is_retryable(e) and attempt < MAX_RETRIES - 1:
                    # Count recoverable throttle retries distinctly so
                    # operators can see how often adaptive-mode's
                    # preemptive slowdown wasn't enough.
                    if _is_throttle(e):
                        _record_error(error_stats,
                                      type("ThrottleRetry", (Exception,),
                                           {})(f"{type(e).__name__}"))
                    logger.warning(
                        f"Retryable error on {name} (attempt {attempt + 1}/{MAX_RETRIES}): "
                        f"{type(e).__name__}: {e}; sleeping {RETRY_BASE_DELAY * (2 ** attempt)}s"
                    )
                    _backoff(attempt)
                    continue
                # Non-retryable, or out of retries: record and re-raise
                # so the whole CR fails fast. Callers that want partial
                # success semantics can wrap per-call.
                logger.error(
                    f"Failed to put {name} after {attempt + 1} attempts: "
                    f"{type(e).__name__}: {e}"
                )
                failures.append({
                    "name": name,
                    "error": f"{type(e).__name__}: {e}",
                    "attempts": attempt + 1,
                })
                raise

        # Apply tags after a successful put. Use a bounded retry set so
        # a transient throttle doesn't lose tagging, but never abort
        # the run if tagging fails permanently.
        if tags:
            _apply_tags(name=name, tags=tags,
                        failures=failures, error_stats=error_stats)

    return count


def _apply_tags(name: str, tags: list, failures: list, error_stats: dict) -> None:
    """
    Tag a single SSM parameter. Non-fatal: any persistent tag failure
    is recorded but does not raise. The parameter value is authoritative;
    missing tags are a cosmetic / billing issue, not a correctness one.

    Throttle budget: same PER_PARAM_THROTTLE_BUDGET_SECONDS wall-clock
    cap as put_parameters(), with the crucial difference that a tag
    throttle-exhaustion is logged and recorded but NOT raised -- losing
    the tag is acceptable; losing the whole run is not.
    """
    _throttle_deadline = time.monotonic() + PER_PARAM_THROTTLE_BUDGET_SECONDS
    for attempt in range(MAX_RETRIES):
        try:
            ssm.add_tags_to_resource(
                ResourceType="Parameter",
                ResourceId=name,
                Tags=tags,
            )
            return
        except Exception as e:
            _record_error(error_stats, e)

            # Tag throttle-exhaustion: record and give up on THIS tag,
            # but continue the run. Tagging is non-fatal.
            if _is_throttle(e) and time.monotonic() >= _throttle_deadline:
                _record_error(error_stats,
                              type("ThrottleExhausted", (Exception,),
                                   {})(f"tag: {type(e).__name__}: {e}"))
                logger.warning(
                    f"Tag throttle budget exhausted on {name} after "
                    f"{attempt + 1} attempts "
                    f"({PER_PARAM_THROTTLE_BUDGET_SECONDS}s wall) -- "
                    f"continuing without tag: {type(e).__name__}: {e}"
                )
                failures.append({
                    "name": name,
                    "error": f"tag ThrottleExhausted after "
                             f"{PER_PARAM_THROTTLE_BUDGET_SECONDS}s: "
                             f"{type(e).__name__}: {e}",
                    "attempts": attempt + 1,
                    "phase": "tag",
                })
                return

            if _is_retryable(e) and attempt < MAX_RETRIES - 1:
                if _is_throttle(e):
                    _record_error(error_stats,
                                  type("ThrottleRetry", (Exception,),
                                       {})(f"tag: {type(e).__name__}"))
                logger.warning(
                    f"Retryable tag error on {name} "
                    f"(attempt {attempt + 1}/{MAX_RETRIES}): "
                    f"{type(e).__name__}: {e}; sleeping "
                    f"{RETRY_BASE_DELAY * (2 ** attempt)}s"
                )
                _backoff(attempt)
                continue
            logger.warning(
                f"Failed to tag {name} after {attempt + 1} attempts "
                f"(continuing): {type(e).__name__}: {e}"
            )
            failures.append({
                "name": name,
                "error": f"tagging failed: {type(e).__name__}: {e}",
                "attempts": attempt + 1,
                "phase": "tag",
            })
            return


def delete_parameters(params: dict, failures: list, error_stats: dict) -> int:
    """
    Delete parameters from SSM in batches of DELETE_BATCH_SIZE.

    Delete failures are logged and added to ``failures`` but never
    raised -- stack deletion must never hang on a stuck parameter. The
    alternative is orphaned params, which is preferable to a
    DELETE_FAILED stack.

    ``error_stats`` accumulates exception class counts (see
    :func:`put_parameters` for semantics).
    """
    names = list(params.keys())
    count = 0
    for i in range(0, len(names), DELETE_BATCH_SIZE):
        batch = names[i : i + DELETE_BATCH_SIZE]
        _throttle_deadline = time.monotonic() + PER_PARAM_THROTTLE_BUDGET_SECONDS
        for attempt in range(MAX_RETRIES):
            try:
                # delete_parameters() does NOT raise for non-existent
                # names -- they are silently returned in
                # InvalidParameters. We count only what SSM reports as
                # actually deleted so the run summary reflects reality
                # (callers often re-run Delete during stack rollback,
                # and the orphaned-ghost case is legitimate, not an
                # error).
                _resp = ssm.delete_parameters(Names=batch)
                count += len(_resp.get("DeletedParameters", []) or [])
                _invalid = _resp.get("InvalidParameters", []) or []
                if _invalid:
                    logger.info(
                        f"delete_parameters: {len(_invalid)} name(s) were "
                        f"already absent (InvalidParameters): {_invalid}"
                    )
                break
            except Exception as e:
                _record_error(error_stats, e)

                # Throttle budget on delete: give up on THIS batch, log
                # each name as failed, move on. Delete is never
                # fatal (stack delete must not hang on stuck params).
                if _is_throttle(e) and time.monotonic() >= _throttle_deadline:
                    _record_error(error_stats,
                                  type("ThrottleExhausted", (Exception,),
                                       {})(f"delete: {type(e).__name__}: {e}"))
                    logger.warning(
                        f"Delete throttle budget exhausted on batch of "
                        f"{len(batch)} after {attempt + 1} attempts "
                        f"({PER_PARAM_THROTTLE_BUDGET_SECONDS}s wall) -- "
                        f"skipping batch: {type(e).__name__}: {e}"
                    )
                    for n in batch:
                        failures.append({
                            "name": n,
                            "error": f"delete ThrottleExhausted after "
                                     f"{PER_PARAM_THROTTLE_BUDGET_SECONDS}s: "
                                     f"{type(e).__name__}: {e}",
                            "attempts": attempt + 1,
                        })
                    break

                if _is_retryable(e) and attempt < MAX_RETRIES - 1:
                    if _is_throttle(e):
                        _record_error(error_stats,
                                      type("ThrottleRetry", (Exception,),
                                           {})(f"delete: {type(e).__name__}"))
                    logger.warning(
                        f"Retryable error deleting batch (attempt {attempt + 1}/{MAX_RETRIES}): "
                        f"{type(e).__name__}: {e}; sleeping {RETRY_BASE_DELAY * (2 ** attempt)}s"
                    )
                    _backoff(attempt)
                    continue
                logger.error(
                    f"Giving up on delete batch of {len(batch)} after "
                    f"{attempt + 1} attempts: {type(e).__name__}: {e}"
                )
                for n in batch:
                    failures.append({
                        "name": n,
                        "error": f"delete failed: {type(e).__name__}: {e}",
                        "attempts": attempt + 1,
                    })
                break  # stop retrying this batch, move on to next
    return count


def _load_params(properties: dict) -> dict:
    """
    Build the final name -> value map by merging the S3 static payload
    with the resolved_params CR property. Either side may be empty.
    resolved_params wins on key collisions so a deploy-time value can
    override a static default if they ever overlap.
    """
    bucket = properties.get("s3_bucket")
    key = properties.get("s3_key")
    resolved_params = properties.get("resolved_params") or {}

    static_params: dict = {}
    if bucket and key:
        static_params = load_payload_from_s3(bucket=bucket, key=key)

    if not isinstance(resolved_params, dict):
        raise ValueError(
            f"resolved_params must be a dict; got {type(resolved_params).__name__}"
        )

    # resolved_params wins on collisions
    merged = {**static_params, **resolved_params}
    logger.info(
        f"Merged parameter set: {len(static_params)} static (S3) + "
        f"{len(resolved_params)} resolved (CR props) -> {len(merged)} total"
    )
    return merged


def lambda_handler(event, context):
    request_type = event.get("RequestType", "")
    properties = event.get("ResourceProperties", {})
    bucket = properties.get("s3_bucket")
    key = properties.get("s3_key")
    content_hash = properties.get("content_hash", "<unset>")
    # Tags to stamp on every parameter this run. Shape matches SSM's
    # AddTagsToResource API: [{"Key": k, "Value": v}, ...]. Missing or
    # empty list disables tagging.
    tags = properties.get("tags") or []
    if tags and not isinstance(tags, list):
        logger.warning(f"tags property must be a list, got {type(tags).__name__}; ignoring")
        tags = []

    logger.info(
        f"BulkSSMWriter: RequestType={request_type} "
        f"s3://{bucket}/{key} content_hash={content_hash} "
        f"tags={len(tags)}"
    )

    # Derive a stable PhysicalResourceId that is constant across
    # Create / Update / Delete for a given CustomResource logical ID.
    #
    # IMPORTANT: If we don't pass physicalResourceId explicitly,
    # cfnresponse.send() defaults it to context.log_stream_name, which
    # changes every time the Lambda runs in a new execution
    # environment. On a stack Update that lands on a cold container,
    # the PhysicalResourceId CFN receives differs from the one it
    # stored at Create. CFN interprets the change as a resource
    # replacement and sends a Delete for the OLD PhysicalResourceId --
    # our Delete handler then removes every SSM parameter we just
    # wrote, silently corrupting the stack's SSM tier.
    #
    # Using event["LogicalResourceId"] (e.g. "BulkSSMStaticParams",
    # "BulkSSMDynamicParams") is stable across Create/Update/Delete and
    # uniquely identifies each CR in the stack.
    physical_resource_id = event.get("LogicalResourceId") or context.log_stream_name

    # End-of-run support summary state. Always emitted exactly once
    # before returning, regardless of success or failure path.
    _start_ts = time.time()
    _failures: list = []
    _error_stats: dict = {}
    _total_params = 0
    _processed_count = 0
    _outcome = "UNKNOWN"
    _outcome_detail = ""

    def _emit_summary() -> None:
        elapsed = time.time() - _start_ts
        # Only log first N failure detail entries to keep the log line
        # manageable; the caller can still pull the log group for the
        # full per-param WARNING/ERROR records above.
        _sample = _failures[:10]
        # Per-exception-type stats -- sorted by count desc for quick
        # operator scanning. Includes *every* exception observed,
        # including retries that eventually succeeded, so the count
        # reflects true API friction, not just permanent failures.
        _errors_by_type = dict(
            sorted(_error_stats.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        logger.info(
            "BulkSSMWriter run summary: "
            f"request_type={request_type} "
            f"outcome={_outcome} "
            f"detail={_outcome_detail!r} "
            f"content_hash={content_hash} "
            f"total_params={_total_params} "
            f"processed={_processed_count} "
            f"failures={len(_failures)} "
            f"errors_by_type={_errors_by_type} "
            f"elapsed_s={elapsed:.2f} "
            f"s3://{bucket}/{key} "
            f"failure_sample={_sample}"
        )

    try:
        if request_type in ("Create", "Update"):
            try:
                params = _load_params(properties)
            except Exception as e:
                _record_error(_error_stats, e)
                raise
            _total_params = len(params)
            _processed_count = put_parameters(params, _failures, _error_stats, tags=tags)
            _outcome = "SUCCESS"
            _outcome_detail = f"wrote {_processed_count}/{_total_params}"
            logger.info(f"Wrote {_processed_count}/{_total_params} SSM parameters")
            _emit_summary()
            cfnresponse.send(
                event, context, cfnresponse.SUCCESS,
                {
                    "Count": str(_processed_count),
                    "ContentHash": content_hash,
                    "Failures": str(len(_failures)),
                },
                physicalResourceId=physical_resource_id,
            )

        elif request_type == "Delete":
            # On Delete, rebuild the map we originally wrote so we know
            # exactly which names to remove. If the S3 object is already
            # gone, fall back to whatever resolved_params we can still
            # see on the old event. Never raise -- stack deletion must
            # not hang on missing parameter state.
            try:
                params = _load_params(properties)
            except s3.exceptions.NoSuchKey as e:
                _record_error(_error_stats, e)
                logger.warning(
                    f"Payload s3://{bucket}/{key} missing on Delete; "
                    f"falling back to resolved_params only"
                )
                params = properties.get("resolved_params") or {}
            except Exception as e:
                _record_error(_error_stats, e)
                logger.warning(
                    f"Could not load payload on Delete ({e}); "
                    f"falling back to resolved_params only"
                )
                params = properties.get("resolved_params") or {}

            _total_params = len(params)
            _processed_count = delete_parameters(params, _failures, _error_stats)
            _outcome = "SUCCESS"
            _outcome_detail = f"deleted {_processed_count}/{_total_params}"
            logger.info(f"Deleted {_processed_count}/{_total_params} SSM parameters")
            _emit_summary()
            cfnresponse.send(
                event, context, cfnresponse.SUCCESS,
                {
                    "Count": str(_processed_count),
                    "Failures": str(len(_failures)),
                },
                physicalResourceId=physical_resource_id,
            )

        else:
            _outcome = "SUCCESS"
            _outcome_detail = f"unhandled RequestType={request_type!r} (noop)"
            _emit_summary()
            cfnresponse.send(
                event, context, cfnresponse.SUCCESS, {},
                physicalResourceId=physical_resource_id,
            )

    except Exception as e:
        _record_error(_error_stats, e)
        _outcome = "FAILED"
        _outcome_detail = f"{type(e).__name__}: {e}"
        logger.exception("BulkSSMWriter failed")
        _emit_summary()
        cfnresponse.send(
            event, context, cfnresponse.FAILED,
            {
                "Error": str(e),
                "Failures": str(len(_failures)),
            },
            physicalResourceId=physical_resource_id,
        )

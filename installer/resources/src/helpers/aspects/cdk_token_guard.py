# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CdkTokenGuardAspect — synth-time validator that fails the CDK app when an
unresolved CDK token has leaked into a deploy-time string surface.

Scope:
  - CfnLaunchTemplate.LaunchTemplateData.UserData
  - CfnInstance.UserData
  - CfnFunction.Environment.Variables (string values)
  - CfnOutput.Value
  - CfnCustomResource.Properties / L2 CustomResource string properties
  - s3_assets.Asset source files (text files <1MB) — catches the
    dcvhs9e pattern where rendered scripts get written to disk and
    uploaded as a CDK Asset, bypassing CDK's Tokenization on
    LT.UserData.

Trigger:
  Any of these placeholder patterns appearing in a resolved string value:
    ${Token[xxx.N]}    [TOKEN[xxx]]    TOKEN.AWS.*
  These are the canonical CDK debug-output formats indicating that a
  Token was eagerly stringified by Python (f-string, str(), .format())
  before CDK could process it.

Per-construct opt-out:
  Any construct may suppress the check by attaching metadata:
      node.node.add_metadata("cdk-token-guard", "skip")
  Pair the opt-out with a code comment explaining why; reviewers should
  reject the opt-out otherwise.

See docs/CdkTokenGuard.md for the full bug→correct migration patterns.
"""

from __future__ import annotations

import os
import pathlib
import re
from typing import Any, Optional

import jsii
from aws_cdk import Annotations, IAspect, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_lambda as aws_lambda
from aws_cdk import aws_s3_assets as s3_assets
from aws_cdk import CfnOutput, CfnResource
from constructs import IConstruct


# Canonical CDK debug-output patterns. These are unique enough that no
# legitimate shell, CFN, or string content will match.
TOKEN_PATTERN = re.compile(r"\$\{Token\[|\[TOKEN\[|TOKEN\.AWS\.")


@jsii.implements(IAspect)
class CdkTokenGuardAspect:
    """CDK Aspect that fails synth on leaked tokens. See module docstring."""

    OPT_OUT_KEY = "cdk-token-guard"
    OPT_OUT_VALUE = "skip"

    # Cap text scans to avoid choking synth on Lambda zips, Docker images,
    # or other large binary assets.
    MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB

    # Suffixes we'll text-scan inside s3_assets.Asset paths.  Conservative:
    # only obviously-text formats.  Lambda zips and binaries are skipped
    # by suffix and (defensively) by size.
    TEXT_SUFFIXES = frozenset({
        ".sh", ".bash", ".txt", ".py", ".json", ".yaml", ".yml",
        ".env", ".conf", ".cfg", ".properties", ".ini", ".toml",
        ".j2", ".tmpl", ".template", ".xml", ".html", ".md",
    })

    # ---------- public IAspect API ----------

    def visit(self, node: IConstruct) -> None:
        if self._is_opted_out(node):
            return

        # CFN-bound string surfaces
        if isinstance(node, ec2.CfnLaunchTemplate):
            self._scan_launch_template(node)
        elif isinstance(node, ec2.CfnInstance):
            self._scan_cfn_instance(node)
        elif isinstance(node, aws_lambda.CfnFunction):
            self._scan_lambda_function(node)
        elif isinstance(node, CfnOutput):
            self._scan_cfn_output(node)
        elif isinstance(node, CfnResource) and node.cfn_resource_type == "AWS::CloudFormation::CustomResource":
            self._scan_custom_resource(node)

        # Asset source files (catches the rendered-script-to-S3 path)
        if isinstance(node, s3_assets.Asset):
            self._scan_s3_asset(node)

    # ---------- per-surface scanners ----------

    def _scan_launch_template(self, node: ec2.CfnLaunchTemplate) -> None:
        ltd = node.launch_template_data
        if ltd is None:
            return
        ud = getattr(ltd, "user_data", None)
        if ud is not None:
            self._scan_value(node, "LaunchTemplateData.UserData", ud)

    def _scan_cfn_instance(self, node: ec2.CfnInstance) -> None:
        ud = getattr(node, "user_data", None)
        if ud is not None:
            self._scan_value(node, "UserData", ud)

    def _scan_lambda_function(self, node: aws_lambda.CfnFunction) -> None:
        env = getattr(node, "environment", None)
        if env is None:
            return
        # CDK exposes environment as a property whose Variables is a dict
        # of {name: value}.  After resolve() it's a real dict-of-string.
        variables = getattr(env, "variables", None)
        if variables is None:
            return
        self._scan_value(node, "Environment.Variables", variables)

    def _scan_cfn_output(self, node: CfnOutput) -> None:
        val = getattr(node, "value", None)
        if val is not None:
            self._scan_value(node, "Output.Value", val)

    def _scan_custom_resource(self, node: CfnResource) -> None:
        props = getattr(node, "_cfn_properties", None) or getattr(node, "cfn_properties", None)
        if props is None:
            return
        self._scan_value(node, "CustomResource.Properties", props)

    def _scan_s3_asset(self, node: s3_assets.Asset) -> None:
        source = self._asset_source_path(node)
        if not source:
            return
        path = pathlib.Path(source)
        if not path.exists():
            return

        if path.is_file():
            self._scan_file(node, path)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    self._scan_file(node, child)

    def _asset_source_path(self, node: s3_assets.Asset) -> Optional[str]:
        # asset_path is the staged hash-name (relative, absent at visit time); the child AssetStaging exposes the real absolute source_path.
        for child in node.node.children:
            src = getattr(child, "source_path", None)
            if src:
                return src
        return None

    # ---------- core scan ----------

    def _scan_value(self, node: IConstruct, field: str, value: Any) -> None:
        """Resolve `value` against the stack and recursively scan strings."""
        try:
            resolved = Stack.of(node).resolve(value)
        except Exception:  # pylint: disable=broad-except
            # Resolution can fail for partially-constructed values during
            # certain Aspect timing edges. We do NOT want to crash synth
            # for our own failure; just skip and let CDK's normal synth
            # validation surface anything truly broken.
            return
        self._scan_resolved(node, field, resolved)

    def _scan_resolved(self, node: IConstruct, field: str, resolved: Any) -> None:
        if isinstance(resolved, str):
            match = TOKEN_PATTERN.search(resolved)
            if match:
                self._fail(node, field, resolved, match.group(0))
            return

        if isinstance(resolved, dict):
            # Fn::Base64 wraps a body we DO want to scan
            if "Fn::Base64" in resolved:
                self._scan_resolved(node, field, resolved["Fn::Base64"])
                return
            # Any other dict (Ref, Fn::Sub, Fn::GetAtt, Fn::Join, etc.)
            # is a CFN-handled intrinsic. CFN substitutes at deploy time;
            # no leak risk. We DO recurse into nested values though, in
            # case a deeper string contains a leak.
            for v in resolved.values():
                self._scan_resolved(node, field, v)
            return

        if isinstance(resolved, list):
            for item in resolved:
                self._scan_resolved(node, field, item)
            return

        # Other primitives (None, int, float, bool) — no leak risk.

    def _scan_file(self, node: s3_assets.Asset, file_path: pathlib.Path) -> None:
        # Suffix gate — skip obvious binary formats
        if file_path.suffix.lower() not in self.TEXT_SUFFIXES:
            return
        try:
            size = file_path.stat().st_size
        except OSError:
            return
        if size > self.MAX_FILE_BYTES:
            return
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return

        match = TOKEN_PATTERN.search(content)
        if match:
            self._fail(
                node,
                f"AssetSource[{file_path}]",
                content,
                match.group(0),
            )

    # ---------- helpers ----------

    def _is_opted_out(self, node: IConstruct) -> bool:
        for entry in node.node.metadata:
            if entry.type == self.OPT_OUT_KEY and entry.data == self.OPT_OUT_VALUE:
                return True
        return False

    def _fail(self, node: IConstruct, field: str, content: str, matched: str) -> None:
        # Report via a CDK error annotation instead of raising, so the Aspect
        # walk continues and every leak is collected + surfaced together by
        # `cdk synth`/`cdk deploy` (same pattern as cdk-nag). Tight context
        # window around the match so the reviewer can spot it at a glance.
        idx = content.find(matched)
        snippet = content[max(0, idx - 40):idx + len(matched) + 40].replace("\n", "\\n")
        Annotations.of(node).add_error(
            f"CDK token leak in {node.node.path} ({field}): "
            f"matched '{matched}'. "
            f"Context: ...{snippet}... "
            f"See docs/CdkTokenGuard.md for the bug-to-correct migration "
            f"patterns and the per-construct opt-out (metadata key "
            f"'{self.OPT_OUT_KEY}'='{self.OPT_OUT_VALUE}')."
        )

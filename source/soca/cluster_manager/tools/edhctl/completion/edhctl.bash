# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# GENERATED FILE -- DO NOT EDIT BY HAND.
# Regenerate with: python3 tests/modules/generate_edhctl_completion.py --write
#
# Bash tab completion for edhctl. It deliberately calls no Python: an edhctl
# invocation reads SSM before it parses argv, so a completion that shelled out
# to edhctl would cost an SSM round trip per Tab press and would stop working
# on a cluster whose config is unreachable. See the generator's docstring.
#
# Registered with 'complete -F' directly rather than by dropping a file into
# /etc/bash_completion.d, so that it needs no bash-completion package.

# Subcommands available at a given command path.
_edhctl_subcommands() {
  case "$1" in
    '') echo 'ad cache config db filesystems hardware-profile keys login-nodes logs mirror nodes notifications pcs schedulers support usb-profile userprefs' ;;
    'ad') echo 'export' ;;
    'cache') echo 'delete get scan set' ;;
    'config') echo 'get history key-exists rollback set snapshot' ;;
    'db') echo 'bloat capacity connections export import locks pitr schema snapshot status table-sizes vacuum' ;;
    'db pitr') echo 'restore window' ;;
    'db snapshot') echo 'create delete list' ;;
    'filesystems') echo 'apply get set update' ;;
    'hardware-profile') echo 'bind list resolve show' ;;
    'keys') echo 'report' ;;
    'login-nodes') echo 'rebuild-bootstrap' ;;
    'logs') echo 'hpc lambda web-interface' ;;
    'logs hpc') echo 'fetch list' ;;
    'logs lambda') echo 'failed fetch list watch' ;;
    'logs web-interface') echo 'failed fetch watch' ;;
    'mirror') echo 'keys recover status' ;;
    'nodes') echo 'create-alwayson delete-alwayson list list-alwayson' ;;
    'notifications') echo 'list subscribe test unsubscribe' ;;
    'pcs') echo 'register' ;;
    'schedulers') echo 'get set update' ;;
    'support') echo 'ack patch verify' ;;
    'support ack') echo 'add list remove' ;;
    'support patch') echo 'apply list' ;;
    'usb-profile') echo 'list show' ;;
    'userprefs') echo 'clear list reconcile show' ;;
    *) return 1 ;;
  esac
}

# Every option spelling accepted at a given command path.
_edhctl_options() {
  case "$1" in
    '') echo '--help' ;;
    'ad') echo '--help' ;;
    'ad export') echo '--help' ;;
    'cache') echo '--help' ;;
    'cache delete') echo '--help --key -k' ;;
    'cache get') echo '--help --key --output -k' ;;
    'cache scan') echo '--help --pattern -p' ;;
    'cache set') echo '--expire --help --key --value -e -k -v' ;;
    'config') echo '--help' ;;
    'config get') echo '--help --key --output -k' ;;
    'config history') echo '--help --key --output -k' ;;
    'config key-exists') echo '--help --key -k' ;;
    'config rollback') echo '--force --help --key --version -k -v' ;;
    'config set') echo '--help --key --value -k -v' ;;
    'config snapshot') echo '--help --output -f' ;;
    'db') echo '--help' ;;
    'db bloat') echo '--help --output --top' ;;
    'db capacity') echo '--help --hours --output' ;;
    'db connections') echo '--help --idle-threshold --output' ;;
    'db export') echo '--dest --exclude --help --output --tables' ;;
    'db import') echo '--allow-region-mismatch --confirm --dry-run --exclude --help --mode --output --src --tables' ;;
    'db locks') echo '--help --output' ;;
    'db pitr') echo '--help' ;;
    'db pitr restore') echo '--confirm --help --latest --name --no-wait --output --restore-type --to --wait' ;;
    'db pitr window') echo '--help --output' ;;
    'db schema') echo '--help --output' ;;
    'db snapshot') echo '--help' ;;
    'db snapshot create') echo '--help --name --no-wait --output --wait' ;;
    'db snapshot delete') echo '--confirm --help --name --output' ;;
    'db snapshot list') echo '--help --output' ;;
    'db status') echo '--help --output' ;;
    'db table-sizes') echo '--help --output --top' ;;
    'db vacuum') echo '--analyze --dry-run --full --help --no-analyze --output --table' ;;
    'filesystems') echo '--help' ;;
    'filesystems apply') echo '--base-os --dry-run --force --help --instance-ids --node-types --output --timeout' ;;
    'filesystems get') echo '--flatten --help --key --output -k' ;;
    'filesystems set') echo '--cifs-share-name --enabled --filesystem-name --force --help --mount-drive-letter --mount-options --mount-path --mount-target --on-mount-failure --provider -d -e -f -m -n -o -p -t' ;;
    'filesystems update') echo '--filesystem-name --force --help --key --provider --value -k -n -p -v' ;;
    'hardware-profile') echo '--help' ;;
    'hardware-profile bind') echo '--clear --help --profile --project --stack --yes' ;;
    'hardware-profile list') echo '--help --output' ;;
    'hardware-profile resolve') echo '--help --output --project --stack' ;;
    'hardware-profile show') echo '--help --output' ;;
    'keys') echo '--help' ;;
    'keys report') echo '--help --output --reclaimable-only --verbose -v' ;;
    'login-nodes') echo '--help' ;;
    'login-nodes rebuild-bootstrap') echo '--base-os --force --help' ;;
    'logs') echo '--help' ;;
    'logs hpc') echo '--help' ;;
    'logs hpc fetch') echo '--ai-assistant --from --help --job-id --limit --log-file --log-level --node --output --to' ;;
    'logs hpc list') echo '--help --job-id --output' ;;
    'logs lambda') echo '--help' ;;
    'logs lambda failed') echo '--help --lines --timeout' ;;
    'logs lambda fetch') echo '--ai-assistant --from --function-name --help --limit --log-level --output --to' ;;
    'logs lambda list') echo '--help --output --timeout' ;;
    'logs lambda watch') echo '--function-name --help --interval --log-level --sns-topic-arn --sns-topic-trigger-log-level --timeout' ;;
    'logs web-interface') echo '--help' ;;
    'logs web-interface failed') echo '--help --lines' ;;
    'logs web-interface fetch') echo '--ai-assistant --from --help --limit --log-file --log-level --output --to' ;;
    'logs web-interface watch') echo '--help --interval --log-file --log-level --timeout' ;;
    'mirror') echo '--help' ;;
    'mirror keys') echo '--degraded-only --help --output' ;;
    'mirror recover') echo '--dry-run --failure-mode --force --help --key --no-wait --output -k' ;;
    'mirror status') echo '--help --output' ;;
    'nodes') echo '--help' ;;
    'nodes create-alwayson') echo '--anonymous-metrics --base-os --capacity-reservation-id --efa-support --force-ri --fsx-lustre --fsx-lustre-deployment-type --fsx-lustre-per-unit-throughput --fsx-lustre-size --fsx-lustre-storage-type --help --ht-support --instance-ami --instance-profile --instance-type --job-owner --job-queue --keep-ebs --nodes --placement-group --root-size --scheduler-identifier --scratch-iops --scratch-size --security-groups --spot-allocation-count --spot-allocation-strategy --spot-price --subnet-ids' ;;
    'nodes delete-alwayson') echo '--alwayson-stack-identifier --force --help' ;;
    'nodes list') echo '--help --node-lifecycles --node-types --scheduler-identifier --stack-id' ;;
    'nodes list-alwayson') echo '--alwayson-identifier --help' ;;
    'notifications') echo '--help' ;;
    'notifications list') echo '--help --output' ;;
    'notifications subscribe') echo '--email --help --output -e' ;;
    'notifications test') echo '--help --message -m' ;;
    'notifications unsubscribe') echo '--email --force --help --subscription-arn -a -e' ;;
    'pcs') echo '--help' ;;
    'pcs register') echo '--cluster-identifier --enabled --force --help --region' ;;
    'schedulers') echo '--help' ;;
    'schedulers get') echo '--flatten --help --output --scheduler-identifier' ;;
    'schedulers set') echo '--binary-folder-paths --enabled --endpoint --force --help --lsf-configuration --manage-host-provisioning --pbs-configuration --provider --scheduler-identifier --slurm-configuration -e' ;;
    'schedulers update') echo '--help --key --scheduler-identifier --value -k -n -v' ;;
    'support') echo '--help' ;;
    'support ack') echo '--help' ;;
    'support ack add') echo '--all-pending --help --output --reason --yes' ;;
    'support ack list') echo '--help --output' ;;
    'support ack remove') echo '--all --help --output' ;;
    'support patch') echo '--help' ;;
    'support patch apply') echo '--dry-run --help --output --yes' ;;
    'support patch list') echo '--help --output' ;;
    'support verify') echo '--export-patch --help --ignore-acknowledgements --output --show-unclassified --target' ;;
    'usb-profile') echo '--help' ;;
    'usb-profile list') echo '--help --output' ;;
    'usb-profile show') echo '--help --output' ;;
    'userprefs') echo '--help' ;;
    'userprefs clear') echo '--apply --help --like --yes' ;;
    'userprefs list') echo '--help --like --output' ;;
    'userprefs reconcile') echo '--apply --help --output --yes' ;;
    'userprefs show') echo '--help --like --output' ;;
    *) return 1 ;;
  esac
}

# Options that take NO value, so the word after them is not an option value.
_edhctl_flags() {
  case "$1" in
    '') echo '--help' ;;
    'ad') echo '--help' ;;
    'ad export') echo '--help' ;;
    'cache') echo '--help' ;;
    'cache delete') echo '--help' ;;
    'cache get') echo '--help' ;;
    'cache scan') echo '--help' ;;
    'cache set') echo '--help' ;;
    'config') echo '--help' ;;
    'config get') echo '--help' ;;
    'config history') echo '--help' ;;
    'config key-exists') echo '--help' ;;
    'config rollback') echo '--force --help' ;;
    'config set') echo '--help' ;;
    'config snapshot') echo '--help' ;;
    'db') echo '--help' ;;
    'db bloat') echo '--help' ;;
    'db capacity') echo '--help' ;;
    'db connections') echo '--help' ;;
    'db export') echo '--help' ;;
    'db import') echo '--allow-region-mismatch --confirm --dry-run --help' ;;
    'db locks') echo '--help' ;;
    'db pitr') echo '--help' ;;
    'db pitr restore') echo '--confirm --help --latest --no-wait --wait' ;;
    'db pitr window') echo '--help' ;;
    'db schema') echo '--help' ;;
    'db snapshot') echo '--help' ;;
    'db snapshot create') echo '--help --no-wait --wait' ;;
    'db snapshot delete') echo '--confirm --help' ;;
    'db snapshot list') echo '--help' ;;
    'db status') echo '--help' ;;
    'db table-sizes') echo '--help' ;;
    'db vacuum') echo '--analyze --dry-run --full --help --no-analyze' ;;
    'filesystems') echo '--help' ;;
    'filesystems apply') echo '--dry-run --force --help' ;;
    'filesystems get') echo '--flatten --help' ;;
    'filesystems set') echo '--force --help' ;;
    'filesystems update') echo '--force --help' ;;
    'hardware-profile') echo '--help' ;;
    'hardware-profile bind') echo '--clear --help --yes' ;;
    'hardware-profile list') echo '--help' ;;
    'hardware-profile resolve') echo '--help' ;;
    'hardware-profile show') echo '--help' ;;
    'keys') echo '--help' ;;
    'keys report') echo '--help --reclaimable-only --verbose -v' ;;
    'login-nodes') echo '--help' ;;
    'login-nodes rebuild-bootstrap') echo '--force --help' ;;
    'logs') echo '--help' ;;
    'logs hpc') echo '--help' ;;
    'logs hpc fetch') echo '--help' ;;
    'logs hpc list') echo '--help' ;;
    'logs lambda') echo '--help' ;;
    'logs lambda failed') echo '--help' ;;
    'logs lambda fetch') echo '--help' ;;
    'logs lambda list') echo '--help' ;;
    'logs lambda watch') echo '--help' ;;
    'logs web-interface') echo '--help' ;;
    'logs web-interface failed') echo '--help' ;;
    'logs web-interface fetch') echo '--help' ;;
    'logs web-interface watch') echo '--help' ;;
    'mirror') echo '--help' ;;
    'mirror keys') echo '--degraded-only --help' ;;
    'mirror recover') echo '--dry-run --force --help --no-wait' ;;
    'mirror status') echo '--help' ;;
    'nodes') echo '--help' ;;
    'nodes create-alwayson') echo '--help' ;;
    'nodes delete-alwayson') echo '--force --help' ;;
    'nodes list') echo '--help' ;;
    'nodes list-alwayson') echo '--help' ;;
    'notifications') echo '--help' ;;
    'notifications list') echo '--help' ;;
    'notifications subscribe') echo '--help' ;;
    'notifications test') echo '--help' ;;
    'notifications unsubscribe') echo '--force --help' ;;
    'pcs') echo '--help' ;;
    'pcs register') echo '--force --help' ;;
    'schedulers') echo '--help' ;;
    'schedulers get') echo '--flatten --help' ;;
    'schedulers set') echo '--force --help' ;;
    'schedulers update') echo '--help' ;;
    'support') echo '--help' ;;
    'support ack') echo '--help' ;;
    'support ack add') echo '--all-pending --help --yes' ;;
    'support ack list') echo '--help' ;;
    'support ack remove') echo '--all --help' ;;
    'support patch') echo '--help' ;;
    'support patch apply') echo '--dry-run --help --yes' ;;
    'support patch list') echo '--help' ;;
    'support verify') echo '--help --ignore-acknowledgements --show-unclassified' ;;
    'usb-profile') echo '--help' ;;
    'usb-profile list') echo '--help' ;;
    'usb-profile show') echo '--help' ;;
    'userprefs') echo '--help' ;;
    'userprefs clear') echo '--apply --help --yes' ;;
    'userprefs list') echo '--help' ;;
    'userprefs reconcile') echo '--apply --help --yes' ;;
    'userprefs show') echo '--help' ;;
    *) return 1 ;;
  esac
}

# Fixed value sets, from click.Choice.
_edhctl_choices() {
  case "$1|$2" in
    'cache get|--output') echo 'json text yaml' ;;
    'config get|--output') echo 'json text yaml' ;;
    'config history|--output') echo 'json text yaml' ;;
    'config snapshot|--output') echo 'json text yaml' ;;
    'config snapshot|-f') echo 'json text yaml' ;;
    'db bloat|--output') echo 'json text' ;;
    'db capacity|--output') echo 'json text' ;;
    'db connections|--output') echo 'json text' ;;
    'db export|--output') echo 'json text' ;;
    'db import|--mode') echo 'replace upsert' ;;
    'db import|--output') echo 'json text' ;;
    'db locks|--output') echo 'json text' ;;
    'db pitr restore|--output') echo 'json text' ;;
    'db pitr restore|--restore-type') echo 'copy-on-write full-copy' ;;
    'db pitr window|--output') echo 'json text' ;;
    'db schema|--output') echo 'json text' ;;
    'db snapshot create|--output') echo 'json text' ;;
    'db snapshot delete|--output') echo 'json text' ;;
    'db snapshot list|--output') echo 'json text' ;;
    'db status|--output') echo 'json text' ;;
    'db table-sizes|--output') echo 'json text' ;;
    'db vacuum|--output') echo 'json text' ;;
    'filesystems apply|--base-os') echo 'amazonlinux2 amazonlinux2023 amazonlinux2027 rhel8 rhel9 rocky8 rocky9 ubuntu2204 ubuntu2404' ;;
    'filesystems apply|--node-types') echo 'compute_node controller dcv_node login_node target_node' ;;
    'filesystems apply|--output') echo 'json text yaml' ;;
    'filesystems get|--output') echo 'json text yaml' ;;
    'filesystems set|--enabled') echo 'false true' ;;
    'filesystems set|--on-mount-failure') echo 'exit ignore' ;;
    'filesystems set|--provider') echo 'efs fsx_lustre fsx_ontap fsx_openzfs nfs s3' ;;
    'filesystems set|-e') echo 'false true' ;;
    'filesystems set|-f') echo 'exit ignore' ;;
    'filesystems set|-p') echo 'efs fsx_lustre fsx_ontap fsx_openzfs nfs s3' ;;
    'filesystems update|--key') echo 'cifs_share_name enabled mount_drive_letter mount_options mount_path mount_target svm_file_system_administrators_group svm_netbios_name svm_organizational_unit' ;;
    'filesystems update|--provider') echo 'efs fsx_lustre fsx_ontap fsx_openzfs nfs s3' ;;
    'filesystems update|-k') echo 'cifs_share_name enabled mount_drive_letter mount_options mount_path mount_target svm_file_system_administrators_group svm_netbios_name svm_organizational_unit' ;;
    'filesystems update|-p') echo 'efs fsx_lustre fsx_ontap fsx_openzfs nfs s3' ;;
    'keys report|--output') echo 'json text yaml' ;;
    'login-nodes rebuild-bootstrap|--base-os') echo 'amazonlinux2 amazonlinux2023 amazonlinux2027 rhel8 rhel9 rocky8 rocky9 ubuntu2204 ubuntu2404' ;;
    'logs hpc fetch|--log-level') echo 'CRITICAL DEBUG ERROR INFO WARNING' ;;
    'logs hpc fetch|--output') echo 'json text' ;;
    'logs hpc list|--output') echo 'json text' ;;
    'logs lambda fetch|--log-level') echo 'CRITICAL DEBUG ERROR INFO WARNING' ;;
    'logs lambda fetch|--output') echo 'json text' ;;
    'logs lambda list|--output') echo 'json text' ;;
    'logs lambda watch|--log-level') echo 'CRITICAL DEBUG ERROR INFO WARNING' ;;
    'logs lambda watch|--sns-topic-trigger-log-level') echo 'CRITICAL ERROR FATAL' ;;
    'logs web-interface fetch|--log-file') echo 'uwsgi web_interface' ;;
    'logs web-interface fetch|--log-level') echo 'CRITICAL DEBUG ERROR INFO WARNING' ;;
    'logs web-interface fetch|--output') echo 'json text' ;;
    'logs web-interface watch|--log-file') echo 'uwsgi web_interface' ;;
    'logs web-interface watch|--log-level') echo 'CRITICAL DEBUG ERROR INFO WARNING' ;;
    'mirror keys|--output') echo 'json text yaml' ;;
    'mirror recover|--failure-mode') echo 'hard soft' ;;
    'mirror recover|--output') echo 'json text yaml' ;;
    'mirror status|--output') echo 'json text yaml' ;;
    'nodes create-alwayson|--base-os') echo 'amazonlinux2 amazonlinux2023 amazonlinux2027 rhel8 rhel9 rocky8 rocky9 ubuntu2204 ubuntu2404' ;;
    'nodes create-alwayson|--spot-allocation-strategy') echo 'capacity-optimized diversified lowest-price' ;;
    'nodes list|--node-lifecycles') echo 'alwayson ondemand' ;;
    'nodes list|--node-types') echo 'compute_node controller dcv_node login_node target_node' ;;
    'notifications list|--output') echo 'json text yaml' ;;
    'notifications subscribe|--output') echo 'json text yaml' ;;
    'pcs register|--enabled') echo 'false true' ;;
    'schedulers get|--output') echo 'json text yaml' ;;
    'schedulers set|--enabled') echo 'false true' ;;
    'schedulers set|--manage-host-provisioning') echo 'false true' ;;
    'schedulers set|--provider') echo 'aws_pcs lsf openpbs slurm' ;;
    'schedulers set|-e') echo 'false true' ;;
    'schedulers update|--key') echo 'binary_folder_paths enabled endpoint lsf_configuration pbs_configuration slurm_configuration soca_managed_nodes_provisioning' ;;
    'schedulers update|-k') echo 'binary_folder_paths enabled endpoint lsf_configuration pbs_configuration slurm_configuration soca_managed_nodes_provisioning' ;;
    'support ack add|--output') echo 'json text yaml' ;;
    'support ack list|--output') echo 'json text yaml' ;;
    'support ack remove|--output') echo 'json text yaml' ;;
    'support patch apply|--output') echo 'json text yaml' ;;
    'support patch list|--output') echo 'json text yaml' ;;
    'support verify|--output') echo 'json text yaml' ;;
    'support verify|--target') echo 'all code installer' ;;
    'userprefs list|--output') echo 'json text' ;;
    'userprefs reconcile|--output') echo 'json text' ;;
    'userprefs show|--output') echo 'json text' ;;
    *) return 1 ;;
  esac
}

# Seam for value completions that need to read something. Anything added here
# must stay free of an AWS call, or Tab pays for it. Returning non-zero means
# "no opinion" and lets the caller fall through to click.Choice values.
_edhctl_value_words() {
  return 1
}

# Whether a space-separated list ($1) contains an exact word ($2). Kept in pure
# bash rather than grep -w: this runs several times per Tab press, and a leading
# '-' makes a word-boundary regex the wrong tool for the job.
_edhctl_contains() {
  local _candidate
  for _candidate in $1; do
    if [[ ${_candidate} == "$2" ]]; then
      return 0
    fi
  done
  return 1
}

_edhctl_completion() {
  local _cur _prev _word _path _candidate _i _skip_value _words _known
  _cur="${COMP_WORDS[COMP_CWORD]}"
  _prev=""
  if [[ ${COMP_CWORD} -gt 0 ]]; then
    _prev="${COMP_WORDS[COMP_CWORD-1]}"
  fi

  # Resolve how deep into the command tree the cursor sits. A word is only
  # allowed to extend the path when it names a real node, which keeps an option
  # value such as `--output json` from being mistaken for a subcommand.
  _path=""
  _skip_value="no"
  for (( _i=1; _i<COMP_CWORD; _i++ )); do
    _word="${COMP_WORDS[_i]}"
    if [[ ${_skip_value} == "yes" ]]; then
      _skip_value="no"
      continue
    fi
    case "${_word}" in
      -*)
        # An option that takes a value swallows the next word.
        _known="$(_edhctl_options "${_path}" 2>/dev/null)" || _known=""
        if _edhctl_contains "${_known}" "${_word}"; then
          _known="$(_edhctl_flags "${_path}" 2>/dev/null)" || _known=""
          if ! _edhctl_contains "${_known}" "${_word}"; then
            _skip_value="yes"
          fi
        fi
        continue
        ;;
    esac
    _candidate="${_path:+${_path} }${_word}"
    if _edhctl_subcommands "${_candidate}" >/dev/null 2>&1 \
      || _edhctl_options "${_candidate}" >/dev/null 2>&1; then
      _path="${_candidate}"
    fi
  done

  # Completing the value of an option rather than a word of the command itself.
  if [[ -n ${_prev} && ${_prev} == -* ]]; then
    _known="$(_edhctl_options "${_path}" 2>/dev/null)" || _known=""
    if _edhctl_contains "${_known}" "${_prev}"; then
      _words="$(_edhctl_flags "${_path}" 2>/dev/null)" || _words=""
      if ! _edhctl_contains "${_words}" "${_prev}"; then
        _words="$(_edhctl_value_words "${_path}" "${_prev}" 2>/dev/null)" \
          || _words="$(_edhctl_choices "${_path}" "${_prev}" 2>/dev/null)" \
          || _words=""
        if [[ -n ${_words} ]]; then
          COMPREPLY=( $(compgen -W "${_words}" -- "${_cur}") )
        else
          # No known value set. Offer filenames rather than command words,
          # which would always be wrong in a value position.
          COMPREPLY=( $(compgen -f -- "${_cur}") )
        fi
        return 0
      fi
    fi
  fi

  if [[ ${_cur} == -* ]]; then
    _words="$(_edhctl_options "${_path}" 2>/dev/null)" || _words=""
  else
    _words="$(_edhctl_subcommands "${_path}" 2>/dev/null)" || _words=""
    # A leaf command has no subcommands, so its options are the useful answer.
    if [[ -z ${_words} ]]; then
      _words="$(_edhctl_options "${_path}" 2>/dev/null)" || _words=""
    fi
  fi
  COMPREPLY=( $(compgen -W "${_words}" -- "${_cur}") )
  return 0
}

complete -F _edhctl_completion edhctl
complete -F _edhctl_completion socactl

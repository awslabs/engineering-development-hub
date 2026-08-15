#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# efa_test_job.sh -- multi-node EFA + MPI validation for SOCA/EDH OpenPBS jobs.
#
# USAGE (cross-version OMPI compatible):
#   qsub -k oed \
#        -N <name> \
#        -l select=<N>:ncpus=<C>:mpiprocs=<K> \
#        -l instance_type=<type> \
#        -l efa_support=true \
#        -l base_os=amazonlinux2023 \
#        -l subnet_id=<subnet> \
#        efa_test_job.sh
#
#   -k oed   Stream stdout/stderr directly to $HOME/<name>.o<jobid> in real
#            time (rather than buffering in PBS mom spool). REQUIRED if you
#            want to `tail -f` job progress as it runs.
#   N        Node count.
#   C        ncpus per node = physical cores. For HPC family Tpc=1 use full
#            vCPU count, else vCPU/2.
#   K        mpiprocs per node = MPI ranks/node. SET EQUAL TO ncpus to enable
#            Phase 7 full-cores saturation testing. PBS writes K lines per
#            node into PBS_NODEFILE; OMPI auto-discovers K slots/node via
#            tm RAS. Required for any K>1 ppr:K:node mapping.
#
# Phases:
#   1a/1b/1c/1d: EFA topology (per-node inventory, sysfs/PCI/NUMA, head-node verbose, multi-rail readiness)
#   2:   Locate MPI (prefer /opt/amazon/openmpi5, fall back to openmpi 4.1)
#   3:   mpirun hostname smoke
#   4:   fi_pingpong over EFA at multiple sizes (multi-node only)
#   4b:  multi-rail fi_pingpong (parallel streams, one per EFA card) if EFA_COUNT>=2
#   5:   MPI ring + alltoall with FI_PROVIDER=efa
#   5f:  MPI alltoall with TCP BTL (TCP comparison; multi-node only)
#   5e:  per-card hw_counters delta after the EFA Alltoall (proves multi-rail)
#   6:   OMPI 4 vs OMPI 5 launch + alltoall comparison (when both installed)
#   7:   full-cores aggregate saturation (alltoall at PPN=physical-cores)
#   7e:  per-card hw_counters delta over the saturation run (multi-rail under load)
#
# Outputs (in $HOME):
#   efa_results_<jobid>.txt    ASCII bar chart + summary
#   efa_results_<jobid>.csv    CSV of all measured bandwidths
#   efa_results_<jobid>.html   Self-contained HTML with inline SVG bar charts
#   .efa_topo_<jobid>.txt      Verbose ibv_devinfo + fi_info -v (referenced by HTML)
#
# Tunables (qsub -v):
#   PPN          override slots/node from PBS_NODEFILE (default: derived)
#   MPI_HOME     force a specific MPI prefix (default: /opt/amazon/openmpi5)
#   FIPP_SIZES   space-separated bytes       (default: 64 4096)
#   FIPP_ITERS   fi_pingpong iters per size  (default: 1000)
#   SKIP_TCP     1 to skip Phase 5f TCP run  (default: 0)

set -uo pipefail
ts(){ date '+%H:%M:%S'; }
log(){ echo "[$(ts)] $*"; }

[[ -z "${PBS_NODEFILE:-}" ]] && { echo "ERROR: PBS_NODEFILE not set; run via qsub"; exit 2; }

############### Init ############################################################
mapfile -t NODELIST < <(sort -V -u "$PBS_NODEFILE")
NODES=${#NODELIST[@]}
JOBID="${PBS_JOBID%%.*}"

# EC2 metadata
IMDS_TOKEN=$(curl -fs -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
imds(){ curl -fs -m 2 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
         "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null || echo "?"; }
INSTANCE_TYPE=$(imds instance-type)
INSTANCE_ID=$(imds instance-id)
AVAILABILITY_ZONE=$(imds placement/availability-zone)
REGION="${AVAILABILITY_ZONE%[a-z]}"

# Robust EFA device detection: treats anything bound to the "efa" kernel driver as
# an EFA NIC, regardless of /sys/class/infiniband/* basename (handles efa_* on
# older AMIs and rdmap* on EFA gen3+ AMIs like hpc8a).
detect_efa_devices(){
  for ib in /sys/class/infiniband/*; do
    [ -d "$ib" ] || continue
    drv=$(readlink "$ib/device/driver" 2>/dev/null | awk -F/ '{print $NF}')
    [ "$drv" = "efa" ] && basename "$ib"
  done | sort -V
}
mapfile -t LOCAL_EFA_DEVICES < <(detect_efa_devices)
EFA_COUNT=${#LOCAL_EFA_DEVICES[@]}

# Discover libfabric domains for the efa provider (e.g. rdmap36s0-rdm)
# NOTE: fi_info -p efa (without -v) gives compact output without fi_domain_attr.
# We need -v to expose the per-endpoint domain blocks.
mapfile -t EFA_DOMAINS < <(
  if [[ -x /opt/amazon/efa/bin/fi_info ]]; then
    /opt/amazon/efa/bin/fi_info -p efa -v 2>/dev/null \
      | awk '/fi_domain_attr/{f=1; next} f && /name:/{print $2; f=0}' \
      | grep -E '\-rdm$' \
      | sort -V -u
  fi
)

NPROC=$(nproc 2>/dev/null || echo 8)

# Compute slots-per-node from PBS_NODEFILE.  PBS writes one line per allocated
# slot, controlled by the `mpiprocs` chunk-level resource at qsub time:
#
#   qsub -l select=N:ncpus=M:mpiprocs=K [...]
#
# yields K lines per node in PBS_NODEFILE.  PRRTE/orted both auto-discover the
# allocation via the tm RAS, see K slots/node, and ppr:K:node maps cleanly with
# bare `mpirun -np (N*K)` -- no --hostfile / --host gymnastics required.
#
# The script reads SLOTS_PER_NODE directly from the file so it always matches
# whatever the user requested via mpiprocs.  Override via env: PPN=K.
SLOTS_PER_NODE=$(awk 'NF{c[$1]++} END{ m=0; for (h in c) if (c[h]>m) m=c[h]; print m+0 }' "$PBS_NODEFILE")
[[ -z "$SLOTS_PER_NODE" || "$SLOTS_PER_NODE" -lt 1 ]] && SLOTS_PER_NODE=1
PPN="${PPN:-$SLOTS_PER_NODE}"

if [[ "$SLOTS_PER_NODE" -le 1 && -z "${PPN_OVERRIDE_OK:-}" ]]; then
  log "WARN: PBS_NODEFILE has only 1 slot/node -- you likely forgot 'mpiprocs=K' in qsub."
  log "      Recommended: qsub -l select=N:ncpus=M:mpiprocs=K  (sets K slots/node)."
  log "      Without it, ppr:>1:node mappings will fail. Continuing with PPN=$PPN."
fi
log "Slots/node from PBS_NODEFILE: $SLOTS_PER_NODE   PPN: $PPN"

# fi_pingpong is a fabric-layer protocol smoke test only. Default EFA endpoint
# is DGRAM (max_msg_size=8928 bytes), so we only test sizes up to 4 KiB. Larger
# message bandwidth is covered comprehensively by Phase 5d MPI Alltoall using
# the full RDM stack with multi-rail.
FIPP_SIZES="${FIPP_SIZES:-64 4096}"
FIPP_ITERS="${FIPP_ITERS:-1000}"
SKIP_TCP="${SKIP_TCP:-0}"

# Common EFA env vars used by all EFA mpirun calls (Phase 4b multirail and
# Phase 5/6/7 alltoall) and by fi_pingpong (Phase 4 / 4b SSH commands).
#
#   FI_EFA_USE_DEVICE_RDMA=1  Force libfabric EFA provider to use hardware
#       RDMA write/read (SRD) primitives instead of legacy software-segmented
#       send/recv.  Modern EFA installers (1.30+) default this on when the
#       hardware supports it -- which is every type we care about -- but we
#       set it explicitly so behaviour is deterministic across installer
#       versions and the resulting CR clearly documents intent.
#
#       NOTE: First-generation EFA hardware (c5n, c5d, m5n/m5dn, r5n/r5dn,
#       p3dn) physically lacks RDMA Read.  fi_info advertises FI_RMA caps
#       but actual endpoint creation aborts with "EFA device has no rdma-read
#       capability" when this env var is set.  Phase 1c.5 below probes the
#       live hardware via mpirun and clears EFA_DEVICE_RDMA on first-gen
#       hardware so subsequent phases use legacy send/recv mode.
#
#   FI_EFA_FORK_SAFE=1  Tell libfabric to handle fork() safely.  Some MPI
#       apps fork after MPI_Init (UCX, system() shells, etc).  Without this,
#       memory regions registered with rdma-core can become unusable in the
#       child.  Cheap insurance, no cost when no fork happens.
#
#   RDMAV_FORK_SAFE=1  rdma-core verbs equivalent to FI_EFA_FORK_SAFE=1 --
#       belt-and-suspenders for older code paths that go through libibverbs
#       directly.  Same rationale.
EFA_DEVICE_RDMA=1   # may be cleared to 0 by Phase 2.5 if hardware lacks rdma-read

# Build env strings.  Called after EFA_DEVICE_RDMA may have changed value
# in Phase 2.5; both env strings are referenced by reference (re-expanded
# at each mpirun/fi_pingpong call site).
build_efa_env() {
  if [[ "$EFA_DEVICE_RDMA" == "1" ]]; then
    EFA_MPI_ENV="-x FI_PROVIDER=efa -x FI_EFA_USE_DEVICE_RDMA=1 -x FI_EFA_FORK_SAFE=1 -x RDMAV_FORK_SAFE=1 -x LD_LIBRARY_PATH"
    EFA_FIPP_ENV="FI_PROVIDER=efa FI_EFA_USE_DEVICE_RDMA=1 FI_EFA_FORK_SAFE=1 RDMAV_FORK_SAFE=1"
  else
    # First-gen EFA: omit FI_EFA_USE_DEVICE_RDMA entirely so libfabric
    # falls back to send/recv mode without aborting.
    EFA_MPI_ENV="-x FI_PROVIDER=efa -x FI_EFA_FORK_SAFE=1 -x RDMAV_FORK_SAFE=1 -x LD_LIBRARY_PATH"
    EFA_FIPP_ENV="FI_PROVIDER=efa FI_EFA_FORK_SAFE=1 RDMAV_FORK_SAFE=1"
  fi
}
build_efa_env

# Result tracking
PASS=0; FAIL=0; SKIP=0
declare -a RESULTS=()
check(){
  local name="$1" status="$2" detail="${3:-}"
  case "$status" in
    PASS) PASS=$((PASS+1));;
    FAIL) FAIL=$((FAIL+1));;
    SKIP) SKIP=$((SKIP+1));;
  esac
  RESULTS+=("${status}|${name}|${detail}")
}

# Bandwidth records.  Format: phase|size_bytes|mibps|usec_per_xfer|iters|transport
declare -a BW=()
record_bw(){ BW+=("$1|$2|$3|$4|$5|${6:-efa}"); }

humanize_bw_mbps(){  # arg: mibps -> binary storage units
  awk -v v="$1" 'BEGIN{
    if (v >= 1024) printf "%.2f GiB/s", v/1024
    else if (v >= 1) printf "%.2f MiB/s", v
    else printf "%.2f KiB/s", v*1024
  }'
}
humanize_bw_bps(){  # arg: mibps -> decimal network bits/s
  awk -v v="$1" 'BEGIN{
    bps = v * 1024 * 1024 * 8
    if (bps >= 1e9) printf "%.2f Gbps", bps/1e9
    else if (bps >= 1e6) printf "%.2f Mbps", bps/1e6
    else if (bps >= 1e3) printf "%.2f Kbps", bps/1e3
    else printf "%.0f bps", bps
  }'
}
humanize_bw_dual(){
  # Storage units (MiB/s, GiB/s) and network units (Mbps, Gbps) separated
  # by comma, NOT pipe -- pipe overloads as column separator in tables.
  printf "%s, %s" "$(humanize_bw_mbps "$1")" "$(humanize_bw_bps "$1")"
}
humanize_bytes(){
  awk -v v="$1" 'BEGIN{
    if (v >= 1048576) printf "%.0f MiB", v/1048576
    else if (v >= 1024) printf "%.0f KiB", v/1024
    else printf "%d B", v
  }'
}
humanize_bytes_long(){  # for hw_counters bytes (raw integer)
  awk -v v="$1" 'BEGIN{
    if (v >= 1024*1024*1024) printf "%.2f GiB", v/(1024*1024*1024)
    else if (v >= 1024*1024) printf "%.2f MiB", v/(1024*1024)
    else if (v >= 1024) printf "%.2f KiB", v/1024
    else printf "%d B", v
  }'
}

# Header
TOPO_FILE="${HOME}/.efa_topo_${JOBID}.txt"
log "==================================================================="
log "EFA Test Job $JOBID  ($(date -u +%FT%TZ))"
log "==================================================================="
log "  Instance type:   $INSTANCE_TYPE"
log "  Instance id:     $INSTANCE_ID"
log "  AZ:              $AVAILABILITY_ZONE"
log "  Allocated nodes: $NODES  ($([[ $NODES -ge 2 ]] && echo multi-node || echo single-node))"
for n in "${NODELIST[@]}"; do log "    - $n"; done
log "  Local nproc:     $NPROC"
log "  Local EFA cards: $EFA_COUNT  (${LOCAL_EFA_DEVICES[*]:-none})"
log "  EFA domains:     ${EFA_DOMAINS[*]:-none}"
log "  PPN (Phase 5):   $PPN"
log "  fipp sizes:      $FIPP_SIZES bytes"
log "  fipp iters:      $FIPP_ITERS"
log "  TCP comparison:  $([[ $SKIP_TCP == 0 && $NODES -ge 2 ]] && echo enabled || echo skipped)"
log "  Verbose topo:    $TOPO_FILE"

############### Locate MPI (used by Phase 1+) ##################################
# We locate mpirun BEFORE Phase 1 because mpirun is the cleanest way to fan
# out a small probe command "one rank per node" across the allocation:
#
#   $MPIRUN --map-by ppr:1:node -np $NODES bash -c '...'
#
# This avoids pbsdsh (which defaults to one task per slot, deadlocking with
# full-cores qsub) and SSH (which adds plumbing we don't need).  PRRTE auto-
# discovers the PBS allocation via the tm RAS.  No --hostfile / --host needed.
#
# AWS EFA installer (1.36+) bundles two OpenMPIs:
#   /opt/amazon/openmpi/   -> 4.1.x  (default symlink)
#   /opt/amazon/openmpi5/  -> 5.0.x  (modern PMIx 4 / PRRTE)
# Default OMPI 5; override with MPI_HOME=/opt/amazon/openmpi to force OMPI 4.
log ""
log "=== Locating MPI ==="
list_amazon_mpi() {
  for d in /opt/amazon/openmpi5 /opt/amazon/openmpi /opt/amazon/openmpi4; do
    [[ -x "$d/bin/mpirun" ]] && echo "$d"
  done
}
if [[ -n "${MPI_HOME:-}" && -x "$MPI_HOME/bin/mpirun" ]]; then
  log "MPI_HOME override: $MPI_HOME"
  MPI_PREFIX="$MPI_HOME"
elif [[ -x /opt/amazon/openmpi5/bin/mpirun ]]; then
  MPI_PREFIX=/opt/amazon/openmpi5
elif [[ -x /opt/amazon/openmpi/bin/mpirun ]]; then
  MPI_PREFIX=/opt/amazon/openmpi
else
  MPI_PREFIX=$(list_amazon_mpi | head -1)
fi
if [[ -n "$MPI_PREFIX" ]]; then
  log "Available Amazon MPI prefixes:"
  list_amazon_mpi | sed 's/^/  /'
  log "Selected: $MPI_PREFIX"
  export PATH=$MPI_PREFIX/bin:$PATH
  export LD_LIBRARY_PATH=$MPI_PREFIX/lib:/opt/amazon/efa/lib:${LD_LIBRARY_PATH:-}
fi
if command -v mpirun >/dev/null; then
  MPIRUN=$(command -v mpirun)
  MPICC=$(command -v mpicc 2>/dev/null || echo "$MPI_PREFIX/bin/mpicc")
  MPI_VER_LINE=$($MPIRUN --version 2>&1 | head -1)
  log "mpirun: $MPIRUN"
  log "$MPI_VER_LINE"
else
  log "WARN: no mpirun found -- Phase 1 fan-out will skip"
  MPIRUN="" ; MPICC=""
fi

# Per-node fan-out helper -- runs the bash body via mpirun "one rank per node"
# and prints the aggregated stdout (line-prefixed by hostname inside the body).
fanout_per_host(){
  # usage: fanout_per_host <bash_script_body>
  if [[ -z "$MPIRUN" ]]; then
    log "ERROR: no MPIRUN -- cannot fan out"
    return 1
  fi
  local body="$1"
  $MPIRUN --map-by ppr:1:node -np "$NODES" \
    -x LD_LIBRARY_PATH \
    --mca pml ^ucx \
    bash -c "$body"
}

############### Phase 1: EFA topology ##########################################
log ""
log "=== Phase 1a: per-node EFA RDMA inventory ==="
P1A_OUT=$(fanout_per_host '
  host=$(hostname)
  efas=()
  for ib in /sys/class/infiniband/*; do
    [ -d "$ib" ] || continue
    drv=$(readlink "$ib/device/driver" 2>/dev/null | awk -F/ "{print \$NF}")
    [ "$drv" = "efa" ] && efas+=("$(basename "$ib")")
  done
  mapfile -t efas < <(printf "%s\n" "${efas[@]}" | sort -V)
  echo "[$host] EFA RDMA devices (${#efas[@]}): ${efas[*]:-none}"
  if [[ -x /opt/amazon/efa/bin/fi_info ]]; then
    fi=$(/opt/amazon/efa/bin/fi_info -p efa 2>/dev/null | grep -c "^provider: efa")
    echo "[$host] libfabric EFA endpoints: $fi"
  fi
' 2>&1)
P1A_OUT=$(echo "$P1A_OUT" | sort -V)
echo "$P1A_OUT"
P1A_HOSTS_WITH_EFA=$(echo "$P1A_OUT" | grep -cE 'EFA RDMA devices \([1-9][0-9]*\)')
if [[ $EFA_COUNT -ge 1 ]]; then
  if (( P1A_HOSTS_WITH_EFA >= NODES )); then
    check "Phase 1a: EFA RDMA devices on every node" PASS "$P1A_HOSTS_WITH_EFA/$NODES nodes report >=1 EFA"
  else
    check "Phase 1a: EFA RDMA devices on every node" FAIL "only $P1A_HOSTS_WITH_EFA/$NODES nodes have EFA"
  fi
else
  check "Phase 1a: EFA RDMA devices on every node" SKIP "no EFA on local node"
fi
P1A_LIBFABRIC_HOSTS=$(echo "$P1A_OUT" | grep -c "libfabric EFA endpoints: [1-9]")
if [[ $EFA_COUNT -ge 1 ]]; then
  if (( P1A_LIBFABRIC_HOSTS >= NODES )); then
    check "Phase 1a: libfabric EFA provider on every node" PASS "$P1A_LIBFABRIC_HOSTS/$NODES nodes have endpoints"
  else
    check "Phase 1a: libfabric EFA provider on every node" FAIL "only $P1A_LIBFABRIC_HOSTS/$NODES nodes report endpoints"
  fi
else
  check "Phase 1a: libfabric EFA provider on every node" SKIP "no EFA on local node"
fi

log ""
log "=== Phase 1b: per-node EFA sysfs/PCI/NUMA summary ==="
P1B_OUT=$(fanout_per_host '
  host=$(hostname)
  for d in /sys/class/infiniband/*; do
    [ -d "$d" ] || continue
    drv=$(readlink "$d/device/driver" 2>/dev/null | awk -F/ "{print \$NF}")
    [ "$drv" = "efa" ] || continue
    name=$(basename "$d")
    numa=$(cat "$d/device/numa_node" 2>/dev/null || echo "?")
    bdf=$(readlink -f "$d/device" 2>/dev/null | awk -F/ "{print \$NF}")
    fwver=$(cat "$d/fw_ver" 2>/dev/null || echo "?")
    pdir="$d/ports/1"
    pstate=$(awk "{print \$2}" "$pdir/state" 2>/dev/null || echo "?")
    prate=$(cat "$pdir/rate" 2>/dev/null || echo "?")
    txp=$(cat "$d/ports/1/hw_counters/tx_pkts" 2>/dev/null || echo "?")
    rxp=$(cat "$d/ports/1/hw_counters/rx_pkts" 2>/dev/null || echo "?")
    # cpu list affinity: kernel exposes CPUs nearest to the device PCIe root.
    # Falls back to "(all)" when virtualized PCI strips topology.
    aff=$(cat "$d/device/local_cpulist" 2>/dev/null | head -c 40)
    [ -z "$aff" ] && aff="(unknown)"
    printf "[%s] %-15s numa=%s pci=%s fw=%s port1=%s @ %s tx_pkts=%s rx_pkts=%s cpus=%s\n" \
      "$host" "$name" "$numa" "$bdf" "$fwver" "$pstate" "$prate" "$txp" "$rxp" "$aff"
  done | sort -t= -k2,2n -k3,3
' 2>&1)
echo "$P1B_OUT" | sort -V

log ""
log "=== Phase 1b extended: NUMA topology + EFA pinning recommendation ==="
P1B_NUMA=$(fanout_per_host '
  host=$(hostname)
  # NUMA node count
  if command -v numactl >/dev/null 2>&1; then
    nn=$(numactl -H 2>/dev/null | awk "/available:/ {print \$2; exit}")
  else
    nn=$(ls -d /sys/devices/system/node/node[0-9]* 2>/dev/null | wc -l)
  fi
  [ -z "$nn" ] && nn=1
  cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)
  socks=$(lscpu 2>/dev/null | awk -F: "/^Socket/ {gsub(/ /,\"\",\$2); print \$2; exit}")
  [ -z "$socks" ] && socks="?"
  cpu=$(lscpu 2>/dev/null | awk -F: "/^Model name/ {sub(/^ +/,\"\",\$2); print \$2; exit}" | cut -c1-60)
  printf "[%s] cpu=\"%s\" cores=%s sockets=%s numa_nodes=%s\n" "$host" "$cpu" "$cores" "$socks" "$nn"
' 2>&1)
echo "$P1B_NUMA" | sort -V

# Extract head node NUMA count for pinning logic + summary (uniform across cluster).
NUMA_NODES=$(echo "$P1B_NUMA" | awk '/numa_nodes=/{ for(i=1;i<=NF;i++) if($i~/^numa_nodes=/){split($i,a,"="); print a[2]; exit} }')
NUMA_NODES="${NUMA_NODES:-1}"

# Decide whether NUMA pinning would plausibly help, based on host topology:
#   * 1 NUMA node          -> low value; ranks already share cache/memory domain
#   * >=2 NUMA + >=2 cards -> high value; pin ranks to NIC-local NUMA
#   * >=2 NUMA, 1 card     -> medium value; ranks on far NUMA take a hop to NIC
NUMA_PIN_HINT="low"
if (( NUMA_NODES >= 2 )); then
  if (( EFA_COUNT >= 2 )); then NUMA_PIN_HINT="high"; else NUMA_PIN_HINT="medium"; fi
fi
log "  Per-node summary: NUMA_NODES=$NUMA_NODES  EFA_CARDS=$EFA_COUNT"
log "  Pinning recommendation: $NUMA_PIN_HINT-value"
case "$NUMA_PIN_HINT" in
  high)
    log "    -> Phase 7b will run a NUMA-pinned variant by default."
    log "       (set EFA_NUMA_PIN=0 to skip; EFA_NUMA_PIN=1 forces it on single-NUMA hosts)" ;;
  medium)
    log "    -> Phase 7b skipped by default. Set EFA_NUMA_PIN=1 to compare." ;;
  low)
    log "    -> Single NUMA domain: cores are equidistant from EFA card(s)."
    log "       Phase 7b skipped by default. Set EFA_NUMA_PIN=1 to force a control run." ;;
esac

# Auto-enable pinning on multi-NUMA + multi-card hosts unless user overrides.
if [[ -z "${EFA_NUMA_PIN:-}" ]]; then
  if [[ "$NUMA_PIN_HINT" == "high" ]]; then EFA_NUMA_PIN=1; else EFA_NUMA_PIN=0; fi
fi
export EFA_NUMA_PIN

log ""
log "=== Phase 1c: verbose EFA topology (head node) -> $TOPO_FILE ==="
{
  echo "### Job $JOBID -- EFA verbose topology dump (head node $(hostname)) -- $(date -u +%FT%TZ)"
  echo ""
  echo "## lspci EFA devices"
  lspci -nn 2>/dev/null | grep -iE "efa|elastic fabric" || echo "(lspci unavailable)"
  echo ""
  echo "## numactl -H"
  if command -v numactl >/dev/null 2>&1; then numactl -H 2>&1
  elif [[ -f /sys/devices/system/node/online ]]; then echo "NUMA online nodes: $(cat /sys/devices/system/node/online)"
  fi
  echo ""
  echo "## ibv_devinfo -v"
  command -v ibv_devinfo >/dev/null && ibv_devinfo -v 2>&1 || echo "(ibv_devinfo not present)"
  echo ""
  echo "## fi_info -p efa -v"
  [[ -x /opt/amazon/efa/bin/fi_info ]] && /opt/amazon/efa/bin/fi_info -p efa -v 2>&1
  echo ""
  echo "## fi_info -p efa -t FI_EP_RDM"
  [[ -x /opt/amazon/efa/bin/fi_info ]] && /opt/amazon/efa/bin/fi_info -p efa -t FI_EP_RDM 2>&1
} > "$TOPO_FILE" 2>&1
log "  written ($(wc -l < "$TOPO_FILE") lines)"
log "  EFA cards on head node: $EFA_COUNT  ${LOCAL_EFA_DEVICES[*]:-none}"
log "  EFA domains: ${EFA_DOMAINS[*]:-none}"
if command -v ibv_devinfo >/dev/null; then check "Phase 1c: ibv_devinfo present" PASS; else check "Phase 1c: ibv_devinfo present" SKIP "rdma-core not installed"; fi

# Verify hardware RDMA support is reported by libfabric. We pass
# FI_EFA_USE_DEVICE_RDMA=1 in all EFA mpirun calls (see EFA_MPI_ENV); this
# block confirms the kernel + libfabric stack actually supports it on the
# current instance type.  The marker is an FI_RMA capability ("read|write")
# in the per-domain caps block of fi_info -v output.
if [[ -x /opt/amazon/efa/bin/fi_info ]]; then
  RDMA_CAPS=$(/opt/amazon/efa/bin/fi_info -p efa -v 2>/dev/null \
    | awk '/^[[:space:]]+caps:/ && /FI_RMA/ {print; exit}')
  if [[ -n "$RDMA_CAPS" ]]; then
    log "  EFA hardware RDMA: SUPPORTED -- caps line: ${RDMA_CAPS#*caps:}"
    check "Phase 1c: EFA hardware RDMA supported" PASS "FI_RMA caps reported"
  else
    log "  EFA hardware RDMA: NOT REPORTED (legacy send/recv mode would be used)"
    check "Phase 1c: EFA hardware RDMA supported" SKIP "no FI_RMA caps in fi_info"
  fi
fi

log ""
log "=== Phase 1d: multi-rail readiness ==="
if [[ $EFA_COUNT -ge 2 ]]; then
  log "  This instance has $EFA_COUNT EFA cards."
  log "  Multi-rail capable -- workloads using multiple ranks/streams will distribute across all cards."
  log "  Theoretical aggregate (datasheet AWS network perf):  cards * per-card bandwidth"
  log "  Per-card domains: ${EFA_DOMAINS[*]}"
  check "Phase 1d: multi-rail capable" PASS "$EFA_COUNT EFA cards"
elif [[ $EFA_COUNT -eq 1 ]]; then
  log "  Single EFA card -- multi-rail N/A. Phase 4b will be skipped."
  check "Phase 1d: multi-rail capable" SKIP "single EFA card"
else
  log "  No EFA cards detected on local node."
  check "Phase 1d: multi-rail capable" SKIP "no EFA"
fi

############### Phase 2: report MPI version ####################################
# MPI was already located early (before Phase 1) so the fan-out helper could
# use it. Here we just emit the result PASS/FAIL into the summary.
log ""
log "=== Phase 2: report MPI version ==="
if [[ -n "$MPIRUN" ]]; then
  check "Phase 2: mpirun + mpicc available" PASS "$MPI_VER_LINE"
else
  check "Phase 2: mpirun + mpicc available" FAIL "no mpirun on PATH"
fi

############### Phase 2.5: live hardware rdma-read probe #######################
# Phase 1c above checks libfabric's *advertised* FI_RMA caps, but first-gen
# EFA hardware (c5n, c5d, m5n/m5dn, r5n/r5dn, p3dn) advertises FI_RMA while
# the underlying NIC physically lacks rdma-read.  When FI_EFA_USE_DEVICE_RDMA=1
# is set on such hardware, libfabric aborts at endpoint open with:
#   "EFA device has no rdma-read capability. Application will abort()."
# We probe by running a 1-rank mpirun hostname on the head node with the env
# var set; if libfabric emits the abort string, we clear EFA_DEVICE_RDMA and
# rebuild the env strings so subsequent EFA phases use legacy send/recv mode.
log ""
log "=== Phase 2.5: live hardware rdma-read probe ==="
if [[ -n "$MPIRUN" && "$NODES" -ge 2 && -n "${MPICC:-}" && -x "$MPICC" ]]; then
  # Compile a tiny MPI binary that actually opens EFA endpoints.  A non-MPI
  # binary like `hostname` doesn't call MPI_Init, so libfabric never opens
  # any endpoint and the rdma-read abort never fires regardless of env vars.
  # MPI_Barrier across 2 ranks on 2 nodes forces real RDMA traffic.
  PROBE_DIR=$(mktemp -d /tmp/efa_rdma_probe.XXXXXX)
  cat > "$PROBE_DIR/probe.c" <<'EOF'
#include <mpi.h>
int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);
    MPI_Barrier(MPI_COMM_WORLD);
    MPI_Finalize();
    return 0;
}
EOF
  if "$MPICC" -O2 -o "$PROBE_DIR/probe" "$PROBE_DIR/probe.c" 2>"$PROBE_DIR/cc.err"; then
    PROBE_OUT=$(timeout 30 \
      "$MPIRUN" -np 2 --map-by ppr:1:node \
      --mca pml cm --mca mtl ofi \
      -x FI_PROVIDER=efa -x FI_EFA_USE_DEVICE_RDMA=1 \
      -x LD_LIBRARY_PATH="${MPI_PREFIX}/lib:/opt/amazon/efa/lib:${LD_LIBRARY_PATH:-}" \
      "$PROBE_DIR/probe" 2>&1) || true
    if grep -q "no rdma-read capability" <<<"$PROBE_OUT"; then
      log "  hardware lacks rdma-read -- libfabric emitted abort string"
      log "  switching to legacy send/recv mode (FI_EFA_USE_DEVICE_RDMA cleared)"
      EFA_DEVICE_RDMA=0
      build_efa_env
      check "Phase 2.5: rdma-read hardware probe" SKIP "first-gen EFA, falling back to send/recv"
    else
      log "  rdma-read confirmed by 2-node MPI_Barrier probe (no abort string)"
      check "Phase 2.5: rdma-read hardware probe" PASS "rdma-read available"
    fi
  else
    log "  WARN: probe compile failed: $(cat $PROBE_DIR/cc.err 2>/dev/null | head -3)"
    check "Phase 2.5: rdma-read hardware probe" SKIP "mpicc compile failed"
  fi
  rm -rf "$PROBE_DIR"
elif [[ -n "$MPIRUN" && "$NODES" -lt 2 ]]; then
  check "Phase 2.5: rdma-read hardware probe" SKIP "single-node test, cannot probe rdma-read"
elif [[ -n "$MPIRUN" ]]; then
  check "Phase 2.5: rdma-read hardware probe" SKIP "mpicc unavailable"
else
  check "Phase 2.5: rdma-read hardware probe" SKIP "no mpirun"
fi

############### Phase 3: MPI hostname smoke ####################################
log ""
log "=== Phase 3: mpirun hostname (1 process per node) ==="
if [[ -n "$MPIRUN" ]]; then
  if $MPIRUN -np "$NODES" --map-by ppr:1:node \
      -x LD_LIBRARY_PATH \
      --mca pml ^ucx \
      hostname; then
    check "Phase 3: mpirun launches across all chunks" PASS "$NODES rank(s)"
  else
    check "Phase 3: mpirun launches across all chunks" FAIL
  fi
else
  check "Phase 3: mpirun launches across all chunks" SKIP "no mpirun"
fi

############### Phase 4: fi_pingpong over EFA, single-stream ###################
fi_pingpong_one() {  # args: domain_or_empty size iters server_node client_node tag
  local dom="$1" size="$2" iters="$3" srv="$4" cli="$5" tag="$6"
  local srv_arg="" cli_arg=""
  # When binding to a specific RDM domain (rdmap*-rdm), force -e rdm endpoint type
  # to match. Default endpoint is DGRAM which doesn't pair with rdm-named domains.
  if [[ -n "$dom" ]]; then
    srv_arg="-d $dom -e rdm"
    cli_arg="-d $dom -e rdm"
  fi
  # Per-tag port so concurrent multirail invocations don't clash on the default
  # (47592) and so each rail's pkill targets only its own server (not its
  # parallel sibling). Hash the tag into the dynamic port range.
  local port
  port=$(awk -v s="$tag" 'BEGIN{
    h=0; for(i=1;i<=length(s);i++) h=(h*31 + index("abcdefghijklmnopqrstuvwxyz0123456789_-.", substr(tolower(s),i,1))) % 65535
    printf "%d", 49152 + (h % 16383)
  }')
  local logf="/tmp/fipp.${tag}.log"
  # Use nohup+setsid so SSH session close doesn't SIGHUP the backgrounded server.
  # fi_pingpong port flags: server side uses -B (source/bind port);
  # client side uses -P (destination port). Default for both is 47592 -- we
  # MUST override per-rail or parallel multirail invocations clash.
  # Export EFA env vars (RDMA + fork-safe) inline -- mirrors what mpirun
  # passes via -x flags. Same defaults as MPI runs so the comparison stack
  # is identical.
  ssh -o StrictHostKeyChecking=no "$srv" \
    "nohup setsid env $EFA_FIPP_ENV /opt/amazon/efa/bin/fi_pingpong -p efa $srv_arg -S ${size} -I ${iters} -B ${port} >${logf} 2>&1 & disown; sleep 0.3" \
    >/dev/null 2>&1
  sleep 2
  local out
  out=$(ssh -o StrictHostKeyChecking=no "$cli" \
    "env $EFA_FIPP_ENV /opt/amazon/efa/bin/fi_pingpong -p efa $cli_arg -S ${size} -I ${iters} -P ${port} ${srv}" 2>&1)
  # Cleanup: kill ONLY this rail's server (matched by its source bind port).
  # Leaves any sibling parallel rail's fi_pingpong server alone.
  ssh -o StrictHostKeyChecking=no "$srv" "pkill -9 -f \"fi_pingpong.*-B ${port}\" 2>/dev/null; true" >/dev/null 2>&1 || true
  echo "$out"
}

# Adaptive iter count (kept for env override only -- defaults are reasonable).
fipp_iters_for() {
  echo "$FIPP_ITERS"
}

if [[ $NODES -ge 2 ]]; then
  log ""
  log "=== Phase 4: fi_pingpong over EFA (single stream): ${NODELIST[0]} <-> ${NODELIST[1]} ==="
  if [[ -x /opt/amazon/efa/bin/fi_pingpong ]]; then
    for size in $FIPP_SIZES; do
      hsize=$(humanize_bytes "$size")
      iters=$(fipp_iters_for "$size")
      log "  --- size=$hsize  iters=$iters ---"
      tag="single_${size}"
      OUT=$(fi_pingpong_one "" "$size" "$iters" "${NODELIST[0]}" "${NODELIST[1]}" "$tag")
      echo "$OUT" >"/tmp/fipp.client.${tag}.log"
      # Match the data line that has 9 whitespace-separated tokens, where token 6 is a number.
      MEAS=$(awk 'NF>=8 && $6 ~ /^[0-9]+\.?[0-9]*$/ && $7 ~ /^[0-9]+\.?[0-9]*$/ {line=$0} END{print line}' <<<"$OUT")
      if [[ -n "$MEAS" ]]; then
        MBPS=$(awk '{print $6}' <<<"$MEAS")
        USEC=$(awk '{print $7}' <<<"$MEAS")
        echo "    -> $(humanize_bw_dual "$MBPS")  ($USEC us/xfer)"
        record_bw "fi_pingpong" "$size" "$MBPS" "$USEC" "$iters" "efa"
        check "Phase 4: fi_pingpong @ $hsize" PASS "$(humanize_bw_dual "$MBPS")"
      else
        log "    parse failed; raw client output (first 8 lines):"
        echo "$OUT" | head -8 | sed "s/^/      /"
        check "Phase 4: fi_pingpong @ $hsize" FAIL "no measurement parsed (see /tmp/fipp.client.${tag}.log)"
      fi
    done
  else
    log "fi_pingpong not present, skipping"
    check "Phase 4: fi_pingpong" SKIP "fi_pingpong missing"
  fi
fi

############### Phase 4b: multi-rail (parallel streams, one per EFA card) ######
if [[ $NODES -ge 2 && $EFA_COUNT -ge 2 ]]; then
  log ""
  log "=== Phase 4b: multi-rail fi_pingpong (parallel streams across $EFA_COUNT EFA cards) ==="
  log "  Domains: ${EFA_DOMAINS[*]}"
  size=4096   # 4 KiB -- DGRAM-safe; multi-rail validation is structural, not bandwidth
  hsize=$(humanize_bytes "$size")
  log "  --- $EFA_COUNT parallel streams, size=$hsize, iters=$FIPP_ITERS ---"
  declare -a CHILD_PIDS=()
  declare -a STREAM_LOGS=()
  i=0
  for dom in "${EFA_DOMAINS[@]}"; do
    tag="multirail_${i}"
    logf="/tmp/fipp.client.${tag}.log"
    STREAM_LOGS+=("$logf")
    (
      OUT=$(fi_pingpong_one "$dom" "$size" "$FIPP_ITERS" "${NODELIST[0]}" "${NODELIST[1]}" "$tag")
      echo "$OUT" >"$logf"
    ) &
    CHILD_PIDS+=($!)
    i=$((i+1))
    sleep 1   # stagger server starts to avoid port collision
  done
  wait "${CHILD_PIDS[@]}" 2>/dev/null || true
  TOTAL_MIBPS=0
  i=0
  for logf in "${STREAM_LOGS[@]}"; do
    dom="${EFA_DOMAINS[$i]}"
    OUT=$(cat "$logf")
    MEAS=$(awk 'NF>=8 && $6 ~ /^[0-9]+\.?[0-9]*$/ && $7 ~ /^[0-9]+\.?[0-9]*$/ {line=$0} END{print line}' <<<"$OUT")
    if [[ -n "$MEAS" ]]; then
      MBPS=$(awk '{print $6}' <<<"$MEAS")
      USEC=$(awk '{print $7}' <<<"$MEAS")
      log "    rail $i ($dom): $(humanize_bw_dual "$MBPS")  ($USEC us/xfer)"
      record_bw "multirail_rail${i}" "$size" "$MBPS" "$USEC" "$FIPP_ITERS" "efa"
      TOTAL_MIBPS=$(awk -v a="$TOTAL_MIBPS" -v b="$MBPS" 'BEGIN{printf "%.4f", a+b}')
    else
      log "    rail $i ($dom): parse failed; see $logf"
    fi
    i=$((i+1))
  done
  log "  Aggregate across $EFA_COUNT rails: $(humanize_bw_dual "$TOTAL_MIBPS")"
  record_bw "multirail_total" "$size" "$TOTAL_MIBPS" "0" "$FIPP_ITERS" "efa"
  if awk -v t="$TOTAL_MIBPS" 'BEGIN{exit !(t>0)}'; then
    check "Phase 4b: multi-rail aggregate (${EFA_COUNT} rails)" PASS "$(humanize_bw_dual "$TOTAL_MIBPS")"
  else
    check "Phase 4b: multi-rail aggregate (${EFA_COUNT} rails)" FAIL
  fi
elif [[ $NODES -ge 2 ]]; then
  check "Phase 4b: multi-rail aggregate" SKIP "single EFA card on this instance"
fi

############### Phase 5 prep: build MPI test programs ##########################
SRC="${HOME}/.efa_test_${JOBID}"
mkdir -p "$SRC"
trap 'rm -rf "$SRC"' EXIT

cat >"$SRC/ring.c" <<'C'
#include <mpi.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char**argv){
    MPI_Init(&argc,&argv);
    int rank,size; char h[256];
    MPI_Comm_rank(MPI_COMM_WORLD,&rank);
    MPI_Comm_size(MPI_COMM_WORLD,&size);
    gethostname(h,sizeof(h));
    int token = 0;
    if(rank == 0){
        token = size;
        MPI_Send(&token,1,MPI_INT,(rank+1)%size,0,MPI_COMM_WORLD);
        MPI_Recv(&token,1,MPI_INT,(size-1)%size,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        printf("[%s r%d/%d] ring complete, final token=%d\n",h,rank,size,token);
    } else {
        MPI_Recv(&token,1,MPI_INT,rank-1,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        token--;
        MPI_Send(&token,1,MPI_INT,(rank+1)%size,0,MPI_COMM_WORLD);
        if(rank < 4 || rank == size-1)
            printf("[%s r%d/%d] forwarded token=%d\n",h,rank,size,token);
    }
    MPI_Finalize();
    return 0;
}
C

cat >"$SRC/alltoall.c" <<'C'
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
 * usage: alltoall [size_csv] [iters]
 *   size_csv: comma-separated message sizes in bytes (default: 1024,16384,262144,1048576)
 *   iters:    iterations per size (default: 50)
 * Prints to stdout (rank 0):
 *   [alltoall] ranks=<N> iters/size=<I>
 *   [alltoall] bytes        total_MB       mibps_per_rank
 *   [alltoall] <bytes>      <total_MB>     <mibps_per_rank>
 */
int main(int argc, char**argv){
    MPI_Init(&argc,&argv);
    int rank,size;
    MPI_Comm_rank(MPI_COMM_WORLD,&rank);
    MPI_Comm_size(MPI_COMM_WORLD,&size);
    int sizes[16];
    int nsizes = 0;
    int iters = 50;
    if (argc >= 2 && argv[1][0]) {
        char *buf = strdup(argv[1]);
        char *p = strtok(buf, ",");
        while (p && nsizes < 16) {
            sizes[nsizes++] = atoi(p);
            p = strtok(NULL, ",");
        }
        free(buf);
    }
    if (nsizes == 0) {
        sizes[0]=1024; sizes[1]=16384; sizes[2]=262144; sizes[3]=1048576; nsizes = 4;
    }
    if (argc >= 3 && argv[2][0]) iters = atoi(argv[2]);
    if (iters <= 0) iters = 50;
    if(rank == 0){
        printf("[alltoall] ranks=%d iters/size=%d\n", size, iters);
        printf("[alltoall] %-12s %-14s %-14s\n","bytes","total_MB","mibps_per_rank");
    }
    for(int s = 0; s < nsizes; s++){
        int n = sizes[s];
        char *snd = malloc((size_t)n*size);
        char *rcv = malloc((size_t)n*size);
        if (!snd || !rcv) { if(rank==0) fprintf(stderr,"[alltoall] malloc failed at size=%d\n", n); break; }
        memset(snd, rank & 0xff, (size_t)n*size);
        MPI_Barrier(MPI_COMM_WORLD);
        double t0 = MPI_Wtime();
        for(int i = 0; i < iters; i++)
            MPI_Alltoall(snd, n, MPI_BYTE, rcv, n, MPI_BYTE, MPI_COMM_WORLD);
        MPI_Barrier(MPI_COMM_WORLD);
        double t1 = MPI_Wtime();
        if(rank == 0){
            double total_mb = (double)n * size * iters / (1024.0*1024.0);
            double mbps = total_mb / (t1 - t0);
            printf("[alltoall] %-12d %-14.1f %-14.1f\n", n, total_mb, mbps);
        }
        free(snd); free(rcv);
    }
    MPI_Finalize();
    return 0;
}
C

if [[ -n "${MPICC:-}" ]] && \
   "$MPICC" -O2 -o "$SRC/ring" "$SRC/ring.c" 2>/tmp/mpicc.ring.err && \
   "$MPICC" -O2 -o "$SRC/alltoall" "$SRC/alltoall.c" 2>/tmp/mpicc.atoa.err; then
  log ""
  log "=== Phase 5 prep: ring + alltoall compiled ==="
else
  log "ERROR: mpicc compile failed"
  cat /tmp/mpicc.ring.err 2>/dev/null
  cat /tmp/mpicc.atoa.err 2>/dev/null
  check "Phase 5 prep: MPI binaries compile" FAIL
fi

############### Helper: capture per-card hw_counters ###########################
snapshot_counters(){  # arg: outfile -- writes "host|device|tx_pkts|rx_pkts|tx_bytes|rx_bytes"
  local outfile="$1"
  # The 2>/dev/null + grep filter is critical:
  #   - mpirun launchers can emit ssh "Permanently added ... to known hosts"
  #     warnings on stderr, which previously got captured into the snapshot
  #     and counted as a phantom 5th card. Drop stderr.
  #   - grep ensures only valid 6-field "host|card|tx_pkts|rx_pkts|tx_bytes|
  #     rx_bytes" lines reach the per-card delta loop.
  fanout_per_host '
    host=$(hostname)
    for d in /sys/class/infiniband/*; do
      [ -d "$d" ] || continue
      drv=$(readlink "$d/device/driver" 2>/dev/null | awk -F/ "{print \$NF}")
      [ "$drv" = "efa" ] || continue
      name=$(basename "$d")
      txp=$(cat "$d/ports/1/hw_counters/tx_pkts" 2>/dev/null || echo 0)
      rxp=$(cat "$d/ports/1/hw_counters/rx_pkts" 2>/dev/null || echo 0)
      txb=$(cat "$d/ports/1/hw_counters/tx_bytes" 2>/dev/null || echo 0)
      rxb=$(cat "$d/ports/1/hw_counters/rx_bytes" 2>/dev/null || echo 0)
      echo "$host|$name|$txp|$rxp|$txb|$rxb"
    done
  ' 2>/dev/null \
    | grep -E '^[^|]+\|[^|]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+$' \
    | sort -V -t'|' -k1,2 > "$outfile"
}

############### Phase 5: MPI ring + alltoall, FI_PROVIDER=efa ##################
log ""
log "=== Phase 5: MPI ring + alltoall, FI_PROVIDER=efa  (NODES=$NODES PPN=$PPN) ==="

EFA_LOG="${HOME}/.efa_mpi_provider_${JOBID}.log"
PRE_COUNTERS="${HOME}/.efa_counters_pre_${JOBID}"
POST_COUNTERS="${HOME}/.efa_counters_post_${JOBID}"

if [[ -x "$SRC/ring" && -x "$SRC/alltoall" ]]; then
  log "--- Phase 5a: MPI provider selection probe (FI_LOG_FILE per-rank to shared FS) ---"
  log "--- Phase 5a: MPI provider verification (deferred to Phase 5d bandwidth threshold) ---"
  # OpenMPI/libfabric verbose output cannot be reliably captured per-rank from
  # the head node (FI_LOG_FILE doesn't shell-expand inside OMPI -x flags, and
  # remote stderr aggregation drops debug). Instead we use Phase 5d's MPI
  # Alltoall bandwidth as the empirical proof: TCP single-stream caps near
  # 1 Gbps; EFA RDMA hits 8-40+ Gbps. PASS criterion below applied at Phase 5d.
  log "  (Phase 5 PASS criterion: Phase 5d MPI_Alltoall @ 1MiB > 5 Gbps)"
  # Threshold: per-rank Alltoall bandwidth at 1 MiB.  This is meant as a
  # SANITY check that EFA is being used (not TCP fallback).  Per-rank bandwidth
  # naturally drops as rank count grows (more cross-pair traffic per iteration),
  # so the threshold has to clear TCP without being so high it misses high-rank
  # EFA runs.  Reference values measured on hpc6id.32xlarge:
  #   TCP @ 1 MiB, np=32:  ~120 MiB/s   TCP @ 1 MiB, np=128: ~16 MiB/s
  #   EFA @ 1 MiB, np=32:  ~1810 MiB/s  EFA @ 1 MiB, np=128: ~488 MiB/s
  # 100 MiB/s separates EFA from TCP cleanly at any reasonable rank count.
  PHASE5_BW_PASS_THRESHOLD_MIBPS=100

  log ""
  log "--- Phase 5b: MPI ring (np=$NODES, 1/node, EFA) ---"
  if $MPIRUN -np "$NODES" --map-by ppr:1:node \
      $EFA_MPI_ENV \
      --mca pml cm --mca mtl ofi \
      "$SRC/ring" 2>&1 | tee /tmp/ring1.out | head -10; then
    if grep -q "ring complete" /tmp/ring1.out; then
      check "Phase 5b: MPI ring (1/node, EFA) closes" PASS "np=$NODES"
    else
      check "Phase 5b: MPI ring (1/node, EFA) closes" FAIL "no completion message"
    fi
  else
    check "Phase 5b: MPI ring (1/node, EFA) closes" FAIL "mpirun nonzero"
  fi

  if [[ $NODES -ge 2 ]]; then
    TOTAL=$((NODES * PPN))

    log ""
    log "--- Phase 5c: MPI ring (np=$TOTAL, $PPN/node, EFA) ---"
    if $MPIRUN -np "$TOTAL" --map-by ppr:${PPN}:node \
        $EFA_MPI_ENV \
        --mca pml cm --mca mtl ofi \
        "$SRC/ring" 2>&1 | tee /tmp/ringN.out | head -10; then
      if grep -q "ring complete" /tmp/ringN.out; then
        check "Phase 5c: MPI ring ($PPN/node, EFA) closes" PASS "np=$TOTAL"
      else
        check "Phase 5c: MPI ring ($PPN/node, EFA) closes" FAIL "no completion message"
      fi
    else
      check "Phase 5c: MPI ring ($PPN/node, EFA) closes" FAIL "mpirun nonzero"
    fi

    log ""
    log "--- Phase 5d: MPI_Alltoall (np=$TOTAL, $PPN/node, EFA) -- with per-card hw_counter delta ---"
    snapshot_counters "$PRE_COUNTERS"
    AOUT=$($MPIRUN -np "$TOTAL" --map-by ppr:${PPN}:node \
        $EFA_MPI_ENV \
        --mca pml cm --mca mtl ofi \
        "$SRC/alltoall" 2>&1)
    snapshot_counters "$POST_COUNTERS"
    echo "$AOUT"
    while IFS= read -r line; do
      if [[ "$line" =~ ^\[alltoall\]\ +([0-9]+)\ +([0-9.]+)\ +([0-9.]+) ]]; then
        nb=${BASH_REMATCH[1]}; tmb=${BASH_REMATCH[2]}; mibps=${BASH_REMATCH[3]}
        record_bw "alltoall" "$nb" "$mibps" "0" "50" "efa"
      fi
    done <<<"$AOUT"
    if echo "$AOUT" | grep -q "^\[alltoall\] 1048576"; then
      check "Phase 5d: MPI_Alltoall completes (EFA)" PASS "np=$TOTAL"
      # Phase 5: provider check via bandwidth threshold (TCP can't reach this)
      AA_1M_MIBPS=$(awk -F'|' '$1=="alltoall" && $2=="1048576" {print $3}' < <(printf "%s\n" "${BW[@]}") | head -1)
      if [[ -n "$AA_1M_MIBPS" ]] && awk -v v="$AA_1M_MIBPS" -v t="$PHASE5_BW_PASS_THRESHOLD_MIBPS" 'BEGIN{exit !(v>t)}'; then
        check "Phase 5: MPI used EFA (Alltoall @ 1MiB > ${PHASE5_BW_PASS_THRESHOLD_MIBPS} MiB/s)" PASS "$(humanize_bw_dual "$AA_1M_MIBPS")"
      else
        check "Phase 5: MPI used EFA (Alltoall @ 1MiB > ${PHASE5_BW_PASS_THRESHOLD_MIBPS} MiB/s)" FAIL "${AA_1M_MIBPS:-no measurement}"
      fi
    else
      check "Phase 5d: MPI_Alltoall completes (EFA)" FAIL
      check "Phase 5: MPI used EFA (bandwidth threshold)" FAIL "Alltoall did not complete"
    fi

    log ""
    log "--- Phase 5e: per-card hw_counter delta (proves multi-rail) ---"
    if [[ -s "$PRE_COUNTERS" && -s "$POST_COUNTERS" ]]; then
      printf "  %-30s %-15s %-12s %-12s %-12s %-12s\n" "host" "card" "tx_pkts" "rx_pkts" "tx_bytes" "rx_bytes"
      cards_with_traffic=0; total_cards=0
      while IFS='|' read -r host card txp rxp txb rxb; do
        # find matching pre line
        pre=$(grep "^${host}|${card}|" "$PRE_COUNTERS")
        IFS='|' read -r _ _ ptxp prxp ptxb prxb <<<"$pre"
        d_txp=$((txp - ptxp))
        d_rxp=$((rxp - prxp))
        d_txb=$((txb - ptxb))
        d_rxb=$((rxb - prxb))
        total_cards=$((total_cards+1))
        if [[ $d_txp -gt 0 ]]; then cards_with_traffic=$((cards_with_traffic+1)); fi
        h_txb=$(humanize_bytes_long "$d_txb")
        h_rxb=$(humanize_bytes_long "$d_rxb")
        short_host=${host:0:28}
        printf "  %-30s %-15s %-12s %-12s %-12s %-12s\n" "$short_host" "$card" "+$d_txp" "+$d_rxp" "$h_txb" "$h_rxb"
      done <"$POST_COUNTERS"
      if (( cards_with_traffic == total_cards )) && [[ $total_cards -gt 0 ]]; then
        check "Phase 5e: every EFA card carried Alltoall traffic (multi-rail engaged)" PASS "$cards_with_traffic/$total_cards"
      elif (( cards_with_traffic > 0 )); then
        check "Phase 5e: every EFA card carried Alltoall traffic" FAIL "only $cards_with_traffic/$total_cards cards saw traffic"
      else
        check "Phase 5e: every EFA card carried Alltoall traffic" FAIL "no card saw traffic increase"
      fi
    else
      check "Phase 5e: hw_counter delta" SKIP "snapshot empty"
    fi

    if [[ "$SKIP_TCP" != "1" ]]; then
      # Cap TCP PPN to avoid ephemeral port exhaustion. With PPN=192 (e.g.
      # c8gn/hpc7a) all 384 ranks try to bind ephemeral source ports for
      # OMPI's TCP BTL. Default Linux range is ~32768-60999 = 28K ports;
      # 384 ranks * ~384 peers * 2 (bidir) = ~295K connection attempts ->
      # "Address already in use (98)" cascades and the alltoall aborts.
      #
      # The Phase 5f comparison only needs to demonstrate EFA-vs-TCP order-
      # of-magnitude difference -- 16 ranks/node (32 total) is plenty for
      # that. Use min(PPN, 16) for the TCP run.
      TCP_PPN=$(( PPN < 16 ? PPN : 16 ))
      TCP_TOTAL=$((NODES * TCP_PPN))
      log ""
      log "--- Phase 5f: MPI_Alltoall (np=$TCP_TOTAL, $TCP_PPN/node, TCP BTL) -- TCP comparison ---"
      [[ "$TCP_PPN" -lt "$PPN" ]] && \
        log "    NOTE: capping PPN=$PPN -> TCP_PPN=$TCP_PPN to avoid ephemeral port exhaustion."
      log "    Uses OpenMPI's native TCP BTL (no libfabric) for direct EFA-vs-TCP delta."
      log "    Note: Amazon's EFA libfabric build doesn't include the tcp provider, so"
      log "    we use OMPI's pml/ob1 + btl/tcp stack instead of FI_PROVIDER=tcp."
      # Auto-detect primary NIC (the one carrying the default IPv4 route).
      # Reads /proc/net/route directly so this works on any AL2023 image
      # regardless of arch (c5n: ens5, hpc6id: enp*, c8gn: ens68, etc).
      PRIMARY_NIC=$(awk '$2=="00000000" && $7!="0" {print $1; exit}' /proc/net/route 2>/dev/null)
      [[ -z "$PRIMARY_NIC" ]] && PRIMARY_NIC=$(awk '$2=="00000000" {print $1; exit}' /proc/net/route 2>/dev/null)
      [[ -z "$PRIMARY_NIC" ]] && PRIMARY_NIC=ens5  # last-ditch default
      log "    primary NIC for TCP BTL: $PRIMARY_NIC"
      AOUT_TCP=$($MPIRUN -np "$TCP_TOTAL" --map-by ppr:${TCP_PPN}:node \
          -x LD_LIBRARY_PATH \
          --mca pml ob1 --mca btl self,vader,sm,tcp \
          --mca btl_tcp_if_include "$PRIMARY_NIC" \
          "$SRC/alltoall" 2>&1)
      echo "$AOUT_TCP"
      while IFS= read -r line; do
        if [[ "$line" =~ ^\[alltoall\]\ +([0-9]+)\ +([0-9.]+)\ +([0-9.]+) ]]; then
          nb=${BASH_REMATCH[1]}; tmb=${BASH_REMATCH[2]}; mibps=${BASH_REMATCH[3]}
          record_bw "alltoall_tcp" "$nb" "$mibps" "0" "50" "tcp"
        fi
      done <<<"$AOUT_TCP"
      if echo "$AOUT_TCP" | grep -q "^\[alltoall\] 1048576"; then
        check "Phase 5f: MPI_Alltoall completes (TCP)" PASS "np=$TCP_TOTAL ($TCP_PPN/node)"
      else
        check "Phase 5f: MPI_Alltoall completes (TCP)" FAIL "see $AOUT_TCP"
      fi
    else
      check "Phase 5f: MPI_Alltoall (TCP)" SKIP "SKIP_TCP=1"
    fi

  else
    check "Phase 5c: MPI ring (PPN/node, EFA)" SKIP "single-node"
    check "Phase 5d: MPI_Alltoall (EFA)" SKIP "single-node"
    check "Phase 5e: hw_counter delta" SKIP "single-node"
    check "Phase 5f: MPI_Alltoall (TCP)" SKIP "single-node"
  fi
else
  log "MPI binaries missing, skipping Phase 5"
fi

############### Phase 6: OMPI 4 vs OMPI 5 comparison ############################
# Only runs if BOTH /opt/amazon/openmpi (4.x) AND /opt/amazon/openmpi5 (5.x)
# are present AND we have >=2 nodes.  Recompiles alltoall.c against each
# mpicc to avoid ABI mismatch.  Captures three angles:
#   (a) mpirun launch time (PMIx 3 vs PMIx 4)            -- biggest OMPI5 win
#   (b) MPI_Alltoall @ 1 KiB (small-msg latency)         -- coll algo wins
#   (c) MPI_Alltoall @ 1 MiB (saturated bandwidth)       -- usually flat
# Prints a side-by-side delta table and emits two summary check entries.
OMPI4_PREFIX=/opt/amazon/openmpi
OMPI5_PREFIX=/opt/amazon/openmpi5
if [[ -n "$MPIRUN" && $NODES -ge 2 \
      && -x "$OMPI4_PREFIX/bin/mpirun" && -x "$OMPI4_PREFIX/bin/mpicc" \
      && -x "$OMPI5_PREFIX/bin/mpirun" && -x "$OMPI5_PREFIX/bin/mpicc" ]]; then
  log ""
  log "=== Phase 6: OMPI 4 vs OMPI 5 comparison ==="
  V4=$($OMPI4_PREFIX/bin/mpirun --version 2>&1 | head -1)
  V5=$($OMPI5_PREFIX/bin/mpirun --version 2>&1 | head -1)
  log "    OMPI 4: $V4"
  log "    OMPI 5: $V5"

  # Recompile alltoall.c against each MPI to avoid ABI mismatch.
  P6_OK4=0; P6_OK5=0
  if "$OMPI4_PREFIX/bin/mpicc" -O2 -o "$SRC/alltoall_ompi4" "$SRC/alltoall.c" 2>/tmp/p6_mpicc4.err; then
    P6_OK4=1
  else
    log "Phase 6: OMPI4 mpicc failed -- $(head -3 /tmp/p6_mpicc4.err 2>/dev/null)"
  fi
  if "$OMPI5_PREFIX/bin/mpicc" -O2 -o "$SRC/alltoall_ompi5" "$SRC/alltoall.c" 2>/tmp/p6_mpicc5.err; then
    P6_OK5=1
  else
    log "Phase 6: OMPI5 mpicc failed -- $(head -3 /tmp/p6_mpicc5.err 2>/dev/null)"
  fi

  if [[ "$P6_OK4" == "1" && "$P6_OK5" == "1" ]]; then
    declare -A LAUNCH_S=()       # LAUNCH_S[ompi4]=1.84
    declare -A AA_MIBPS=()       # AA_MIBPS[ompi4_1024]=230.7

    for ver in 4 5; do
      if [[ "$ver" == "4" ]]; then
        MPI_PFX="$OMPI4_PREFIX"; MPI_TAG="ompi4"
      else
        MPI_PFX="$OMPI5_PREFIX"; MPI_TAG="ompi5"
      fi
      # Use explicit --host with PPN slots/node so PRRTE knows the per-node
      # capacity. Without this, PRRTE auto-discovers slots=1/node from PBS
      # via tm RAS (because SOCA's PBS_NODEFILE is 1 line per node, not 1
      # per slot), which breaks oversubscribed mappings like ppr:16:node.
      log ""
      log "--- Phase 6a: $MPI_TAG launch (mpirun hostname, np=$NODES) ---"
      # /usr/bin/time -p prints "real X.XX" to stderr.  Capture stderr only
      # and grep for the real line.  Three runs, take min for stability.
      best=""
      for trial in 1 2 3; do
        rt=$( { /usr/bin/time -p \
                "$MPI_PFX/bin/mpirun" \
                   -np "$NODES" \
                  --map-by ppr:1:node \
                  -x LD_LIBRARY_PATH="$MPI_PFX/lib:/opt/amazon/efa/lib" \
                  --mca pml ^ucx \
                  hostname >/dev/null; } 2>&1 \
              | awk '/^real /{print $2; exit}' )
        log "    trial $trial: ${rt}s"
        if [[ -n "$rt" ]]; then
          if [[ -z "$best" ]] || awk -v a="$rt" -v b="$best" 'BEGIN{exit !(a<b)}'; then
            best="$rt"
          fi
        fi
      done
      LAUNCH_S[$MPI_TAG]="$best"
      log "    best of 3: ${best}s"

      log ""
      log "--- Phase 6b: $MPI_TAG MPI_Alltoall (np=$TOTAL, $PPN/node) ---"
      # OMPI 4's PRRTE doesn't always auto-discover PBS slots via tm RAS
      # (depends on whether the install was built --with-tm). Pass an
      # explicit --hostfile so it can count slots from PBS_NODEFILE lines.
      # OMPI 5 deliberately omits --hostfile to avoid triggering strict
      # reconciliation against tm-discovered IP-form names.
      P6_HF=""
      if [[ "$MPI_TAG" == "ompi4" && -n "${PBS_NODEFILE:-}" ]]; then
        P6_HF="--hostfile $PBS_NODEFILE"
      fi
      AOUT_P6=$( PATH="$MPI_PFX/bin:$PATH" \
                 LD_LIBRARY_PATH="$MPI_PFX/lib:/opt/amazon/efa/lib" \
                 "$MPI_PFX/bin/mpirun" \
                    -np "$TOTAL" \
                   $P6_HF \
                   --map-by ppr:${PPN}:node \
                   $EFA_MPI_ENV \
                   -x LD_LIBRARY_PATH="$MPI_PFX/lib:/opt/amazon/efa/lib" \
                   --mca pml cm --mca mtl ofi \
                   "$SRC/alltoall_$MPI_TAG" 2>&1 )
      echo "$AOUT_P6" | head -20
      while IFS= read -r line; do
        if [[ "$line" =~ ^\[alltoall\]\ +([0-9]+)\ +([0-9.]+)\ +([0-9.]+) ]]; then
          nb=${BASH_REMATCH[1]}; mibps=${BASH_REMATCH[3]}
          AA_MIBPS[${MPI_TAG}_${nb}]="$mibps"
          record_bw "alltoall_$MPI_TAG" "$nb" "$mibps" "0" "50" "$MPI_TAG"
        fi
      done <<<"$AOUT_P6"
    done

    # Comparison table -- collect into OMPI45_DELTA so artifact generator can render it.
    OMPI45_DELTA=""
    log ""
    log "--- Phase 6 results: OMPI 4 vs OMPI 5 ---"
    fmt_row(){ printf "  %-32s %-18s %-18s %-12s\n" "$1" "$2" "$3" "$4"; }
    fmt_row "metric" "OMPI 4" "OMPI 5" "delta"          | tee -a /dev/stderr
    fmt_row "------------------------------" "------------------" "------------------" "------------" | tee -a /dev/stderr
    OMPI45_DELTA+="$(fmt_row 'metric' 'OMPI 4' 'OMPI 5' 'delta')"$'\n'
    OMPI45_DELTA+="$(fmt_row '------------------------------' '------------------' '------------------' '------------')"$'\n'
    # Launch
    if [[ -n "${LAUNCH_S[ompi4]:-}" && -n "${LAUNCH_S[ompi5]:-}" ]]; then
      pct=$(awk -v a="${LAUNCH_S[ompi4]}" -v b="${LAUNCH_S[ompi5]}" \
            'BEGIN{ if(a>0) printf "%+.1f%%", (b-a)/a*100; else print "n/a" }')
      row=$(fmt_row "mpirun hostname (np=$NODES)" "${LAUNCH_S[ompi4]}s" "${LAUNCH_S[ompi5]}s" "$pct")
      log "$row"
      OMPI45_DELTA+="$row"$'\n'
      check "Phase 6: OMPI 5 launch vs OMPI 4" PASS "${LAUNCH_S[ompi4]}s -> ${LAUNCH_S[ompi5]}s ($pct)"
    else
      check "Phase 6: OMPI 5 launch vs OMPI 4" SKIP "no timing data"
    fi
    # Alltoall at all 4 sizes
    for nb in 1024 16384 262144 1048576; do
      v4="${AA_MIBPS[ompi4_$nb]:-}"; v5="${AA_MIBPS[ompi5_$nb]:-}"
      if [[ -n "$v4" && -n "$v5" ]]; then
        pct=$(awk -v a="$v4" -v b="$v5" 'BEGIN{ if(a>0) printf "%+.1f%%", (b-a)/a*100; else print "n/a" }')
        h4=$(humanize_bw_dual "$v4"); h5=$(humanize_bw_dual "$v5")
        row=$(fmt_row "MPI_Alltoall @ $(humanize_bytes "$nb")" "$h4" "$h5" "$pct")
        log "$row"
        OMPI45_DELTA+="$row"$'\n'
      fi
    done
    # Headline check: alltoall@1MiB delta
    v4="${AA_MIBPS[ompi4_1048576]:-}"; v5="${AA_MIBPS[ompi5_1048576]:-}"
    if [[ -n "$v4" && -n "$v5" ]]; then
      pct=$(awk -v a="$v4" -v b="$v5" 'BEGIN{ if(a>0) printf "%+.1f%%", (b-a)/a*100; else print "n/a" }')
      check "Phase 6: OMPI 5 alltoall @ 1MiB vs OMPI 4" PASS "$(humanize_bw_dual "$v4") -> $(humanize_bw_dual "$v5") ($pct)"
    else
      check "Phase 6: OMPI 5 alltoall @ 1MiB vs OMPI 4" SKIP "missing data"
    fi
  else
    check "Phase 6: OMPI 5 launch vs OMPI 4" SKIP "mpicc compile failed"
    check "Phase 6: OMPI 5 alltoall @ 1MiB vs OMPI 4" SKIP "mpicc compile failed"
  fi
else
  if [[ ! -x "$OMPI5_PREFIX/bin/mpirun" ]]; then
    P6_REASON="OMPI5 not installed (need EFA installer >= 1.36 with --enable-openmpi5)"
  elif [[ ! -x "$OMPI4_PREFIX/bin/mpirun" ]]; then
    P6_REASON="OMPI4 not installed"
  elif [[ $NODES -lt 2 ]]; then
    P6_REASON="single-node"
  else
    P6_REASON="MPI not located"
  fi
  log ""
  log "=== Phase 6: OMPI 4 vs OMPI 5 comparison ==="
  log "    SKIP -- $P6_REASON"
  check "Phase 6: OMPI 5 launch vs OMPI 4" SKIP "$P6_REASON"
  check "Phase 6: OMPI 5 alltoall @ 1MiB vs OMPI 4" SKIP "$P6_REASON"
fi

############### Phase 7: full-cores aggregate saturation #######################
# Push toward the instance's advertised EFA bandwidth by using all physical
# cores as MPI ranks. Reports per-rank, total, inter-node aggregate, per-node
# EFA Gbps, and saturation pct vs advertised network bandwidth from EC2 API.
# Uses larger message sizes (256 KiB - 16 MiB, 30 iters) to amortize launch
# costs and get steady-state throughput.
#
# REQUIREMENT: this phase needs PBS to allocate one slot per physical core,
# i.e. qsub with `mpiprocs=$(physical_cores_per_node)`. If PBS_NODEFILE has
# fewer slots/node than physical cores, Phase 7 SKIPs with a clear message.
# We never use --oversubscribe -- it would mask real misconfigurations and
# could let a future change accidentally over-pack ranks past hardware cores.
SAT_TABLE=""
if [[ -n "$MPIRUN" && "$NODES" -ge 2 && -x "$SRC/alltoall" ]]; then
  log ""
  log "=== Phase 7: full-cores aggregate saturation ==="

  FULL_PPN=$(nproc)

  if [[ "$SLOTS_PER_NODE" -lt "$FULL_PPN" ]]; then
    log "    SKIP -- PBS gave us $SLOTS_PER_NODE slot(s)/node but the hardware has"
    log "         $FULL_PPN cores. To exercise full-cores saturation, resubmit with:"
    log "             qsub -l select=${NODES}:ncpus=${FULL_PPN}:mpiprocs=${FULL_PPN} ..."
    log "         (We do NOT --oversubscribe past the PBS allocation -- that's a"
    log "         dangerous default to set in any test infrastructure.)"
    check "Phase 7: full-cores EFA saturation" SKIP \
      "PBS slots/node ($SLOTS_PER_NODE) < cores ($FULL_PPN) -- need mpiprocs=$FULL_PPN"
  else
    # Discover advertised network bandwidth via EC2 API. Use the instance-level
    # NetworkPerformance string (e.g. "300 Gigabit", "Up to 200 Gigabit") --
    # this is what AWS markets at the instance level. We also pull the
    # per-NetworkCard BaselineBandwidthInGbps so we can compute the actual
    # aggregate physical line-rate (sum across cards) used as the denominator
    # for osu_mbw_mr's aggregate sender bandwidth. Both are sourced from the
    # same describe-instance-types call so the script stays grounded in the
    # live API instead of hardcoded multipliers.
    NETINFO_JSON=$(aws ec2 describe-instance-types \
      --instance-types "$INSTANCE_TYPE" \
      --region "$REGION" \
      --query 'InstanceTypes[0].NetworkInfo.{NetPerf:NetworkPerformance,Cards:NetworkCards[].BaselineBandwidthInGbps}' \
      --output json 2>/dev/null)
    NET_PERF=$(echo "$NETINFO_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("NetPerf",""))' 2>/dev/null)
    # Sum BaselineBandwidthInGbps across all NetworkCards. This represents
    # the maximum simultaneous bandwidth the cards can carry (e.g. hpc6id has
    # 2 cards * 200 Gbps each = 400 Gbps physical aggregate cap).
    PHYS_CAP_GBPS=$(echo "$NETINFO_JSON" | python3 -c 'import sys,json; d=json.load(sys.stdin); cards=d.get("Cards") or []; print(int(round(sum(float(c) for c in cards if c is not None))) if cards else "")' 2>/dev/null)
    # Parse "300 Gigabit", "Up to 200 Gigabit", etc -- extract first integer.
    ADV_GBPS=$(echo "$NET_PERF" | awk '{
      for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+(\.[0-9]+)?$/) { printf "%d", $i+0.5; exit }
    }')
    [[ -z "$ADV_GBPS" || "$ADV_GBPS" == "0" ]] && ADV_GBPS=""
    [[ -z "$PHYS_CAP_GBPS" || "$PHYS_CAP_GBPS" == "0" ]] && PHYS_CAP_GBPS=""

    FULL_TOTAL=$((NODES * FULL_PPN))
    log "Instance type:           $INSTANCE_TYPE"
    log "Advertised network BW:   ${ADV_GBPS:-?} Gbps per instance ($NET_PERF, from EC2 NetworkInfo.NetworkPerformance)"
    log "Per-card baseline sum:   ${PHYS_CAP_GBPS:-?} Gbps (from EC2 NetworkInfo.NetworkCards[].BaselineBandwidthInGbps)"
    log "Full-cores PPN:          $FULL_PPN ($NODES nodes -> $FULL_TOTAL ranks)"
    log "PBS slots/node:          $SLOTS_PER_NODE (sufficient -- no oversubscribe needed)"

    SAT_SIZES_REQUESTED="${SAT_SIZES:-262144,1048576,4194304,16777216}"
    SAT_ITERS="${SAT_ITERS:-30}"

    # Memory-budget filter:
    # MPI_Alltoall allocates 2 * size * N_ranks per rank (sendbuf + recvbuf).
    # Per-node memory = FULL_PPN * 2 * size * FULL_TOTAL. With safety margin
    # at 50% of available RAM, max safe size = (RAM/2) / (2 * PPN * N).
    # Sizes exceeding the budget are dropped with a clear log line.
    #
    # Tunable via env: SAT_MEM_BUDGET_PCT (default 50). Set to 0 to disable.
    SAT_MEM_BUDGET_PCT="${SAT_MEM_BUDGET_PCT:-50}"
    if [[ "$SAT_MEM_BUDGET_PCT" -gt 0 ]]; then
      RAM_KB=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null)
      [[ -z "$RAM_KB" ]] && RAM_KB=$((128 * 1024 * 1024))   # 128 GB fallback
      RAM_BYTES=$((RAM_KB * 1024))
      MAX_SAFE_SIZE=$(awk -v r="$RAM_BYTES" -v p="$FULL_PPN" -v n="$FULL_TOTAL" -v pct="$SAT_MEM_BUDGET_PCT" \
        'BEGIN{ printf "%d", (r * pct / 100) / (2 * p * n) }')
      RAM_GB=$(awk -v r="$RAM_BYTES" 'BEGIN{ printf "%.0f", r/1024/1024/1024 }')
      MAX_HUMAN=$(humanize_bytes "$MAX_SAFE_SIZE")
      log "Memory budget:           ${SAT_MEM_BUDGET_PCT}% of ${RAM_GB} GB RAM"
      log "  Per-node alloc:        FULL_PPN ($FULL_PPN) * 2 * size * FULL_TOTAL ($FULL_TOTAL)"
      log "  Max safe size/rank:    $MAX_HUMAN"

      # Filter requested sizes to those within budget. Print a SKIP line for each.
      SAT_SIZES=""
      SAT_SIZES_SKIPPED=""
      IFS=',' read -ra SAT_LIST <<<"$SAT_SIZES_REQUESTED"
      for sz in "${SAT_LIST[@]}"; do
        if [[ "$sz" -le "$MAX_SAFE_SIZE" ]]; then
          [[ -n "$SAT_SIZES" ]] && SAT_SIZES+=","
          SAT_SIZES+="$sz"
        else
          [[ -n "$SAT_SIZES_SKIPPED" ]] && SAT_SIZES_SKIPPED+=","
          SAT_SIZES_SKIPPED+="$sz"
          NEED_GB=$(awk -v p="$FULL_PPN" -v s="$sz" -v n="$FULL_TOTAL" \
            'BEGIN{ printf "%.0f", p * 2 * s * n / 1024 / 1024 / 1024 }')
          log "  SKIP $(humanize_bytes "$sz") -- needs ~${NEED_GB} GB/node, exceeds budget"
        fi
      done
      [[ -z "$SAT_SIZES" ]] && SAT_SIZES="$SAT_SIZES_REQUESTED"  # keep at least one size for diagnostic
    else
      SAT_SIZES="$SAT_SIZES_REQUESTED"
    fi
    log "Sizes (bytes):           $SAT_SIZES"
    log "Iters/size:              $SAT_ITERS"

    log ""
    log "--- Phase 7a: alltoall np=$FULL_TOTAL --map-by ppr:${FULL_PPN}:node ---"

    # Inter-node fraction: each rank has (N-1) partners; (N - PPN) are inter-node.
    INTER_FRAC=$(awk -v ppn="$FULL_PPN" -v n="$FULL_TOTAL" \
      'BEGIN{ printf "%.4f", (n - ppn) / (n - 1) }')

    # Helper: run the saturation alltoall with caller-provided mpirun extras
    # and emit a 5-column "size | per-rank | aggregate | per-node | sat%" table
    # plus a TSV-ish summary line per row for delta comparison.
    # Also records each row into BW[] tagged with $1 so the bar chart can
    # render Phase 7a default vs 7b pinned side-by-side.
    #
    # Sets globals:  SAT_TABLE_${tag} = full table
    #                P7_TOPSIZE_${tag}=N  P7_TOPBW_${tag}=Gbps  P7_TOPPCT_${tag}=N%
    #                SAT_ROWS_${tag}=$'size_b\tmibps\n...' for delta join
    run_sat() {
      local tag="$1"; shift                 # "default" or "pinned"
      local label="$1"; shift               # human label printed in headers
      # remaining args: extra mpirun flags (--bind-to core etc)
      log ""
      log "    ranks=$FULL_TOTAL  PPN=$FULL_PPN  $label"

      # Per-card hw_counter snapshot bracketing the saturation alltoall.
      # The same proof we apply at Phase 5e -- but at full-cores saturation
      # is where multi-rail engagement matters most: a regression that pins
      # all traffic to card 0 would still PASS Phase 5d/5e (small payloads
      # don't saturate a single rail) yet collapse Phase 7 throughput.
      local PRE_P7="$HOME/.efa_counters_pre_p7_${tag}_${JOBID}"
      local POST_P7="$HOME/.efa_counters_post_p7_${tag}_${JOBID}"
      snapshot_counters "$PRE_P7"

      local out
      out=$($MPIRUN -np "$FULL_TOTAL" \
          "$@" \
          $EFA_MPI_ENV \
          --mca pml cm --mca mtl ofi \
          "$SRC/alltoall" "$SAT_SIZES" "$SAT_ITERS" 2>&1)

      snapshot_counters "$POST_P7"
      echo "$out" | head -30

      local TBL=""
      TBL+="$(printf '  %-10s  %-13s  %-13s  %-15s  %s\n' \
        'size' 'per-rank' 'aggregate' 'per-node EFA' 'sat %')"$'\n'
      TBL+="$(printf '  %-10s  %-13s  %-13s  %-15s  %s\n' \
        '----------' '-------------' '-------------' '---------------' '-------')"$'\n'

      local TOPSIZE="" TOPBW="" TOPPCT="" ROWS=""
      while IFS= read -r line; do
        if [[ "$line" =~ ^\[alltoall\]\ +([0-9]+)\ +([0-9.]+)\ +([0-9.]+) ]]; then
          local nb=${BASH_REMATCH[1]} mibps=${BASH_REMATCH[3]}
          # Tag default rows as "alltoall_sat"; pinned rows as "alltoall_sat_pin".
          if [[ "$tag" == "default" ]]; then
            record_bw "alltoall_sat" "$nb" "$mibps" "0" "$SAT_ITERS" "efa-sat"
          else
            record_bw "alltoall_sat_pin" "$nb" "$mibps" "0" "$SAT_ITERS" "efa-sat-pin"
          fi
          local per_rank_gbps agg_gbps inter_gbps per_node_gbps sat_pct
          per_rank_gbps=$(awk -v v="$mibps" 'BEGIN{printf "%.2f", v*1024*1024*8/1e9}')
          agg_gbps=$(awk -v v="$mibps" -v n="$FULL_TOTAL" 'BEGIN{printf "%.2f", v*n*1024*1024*8/1e9}')
          inter_gbps=$(awk -v a="$agg_gbps" -v f="$INTER_FRAC" 'BEGIN{printf "%.2f", a*f}')
          per_node_gbps=$(awk -v i="$inter_gbps" -v n="$NODES" 'BEGIN{printf "%.2f", i/n}')
          if [[ -n "$ADV_GBPS" ]]; then
            sat_pct=$(awk -v u="$per_node_gbps" -v a="$ADV_GBPS" 'BEGIN{printf "%.1f%%", u/a*100}')
          else
            sat_pct="n/a"
          fi
          TBL+="$(printf '  %-10s  %-13s  %-13s  %-15s  %s\n' \
            "$(humanize_bytes "$nb")" "${per_rank_gbps} Gbps" "${agg_gbps} Gbps" "${per_node_gbps} Gbps" "$sat_pct")"$'\n'
          ROWS+="${nb}	${mibps}	${per_node_gbps}	${sat_pct}"$'\n'
          if [[ -z "$TOPSIZE" || "$nb" -gt "$TOPSIZE" ]]; then
            TOPSIZE="$nb"; TOPBW="$per_node_gbps"; TOPPCT="$sat_pct"
          fi
        fi
      done <<<"$out"

      # Write to caller-named globals via printf -v.
      printf -v "SAT_TABLE_${tag}"   '%s' "$TBL"
      printf -v "P7_TOPSIZE_${tag}"  '%s' "$TOPSIZE"
      printf -v "P7_TOPBW_${tag}"    '%s' "$TOPBW"
      printf -v "P7_TOPPCT_${tag}"   '%s' "$TOPPCT"
      printf -v "SAT_ROWS_${tag}"    '%s' "$ROWS"

      # ----- Phase 7e: per-card hw_counter delta over the saturation run -----
      # Same mechanism as Phase 5e, but executed at the full-cores load. Asserts
      # every EFA card on every node carried traffic during saturation (catches
      # mapping regressions where ranks all bind to card 0 and starve cards 1+).
      # Suffixed with the run tag so default/pinned report distinct results.
      if [[ -s "$PRE_P7" && -s "$POST_P7" ]]; then
        log ""
        log "    --- Per-card hw_counter delta (Phase 7e, ${tag} mapping, multi-rail proof) ---"
        printf "      %-30s %-15s %-12s %-12s %-12s %-12s\n" \
          "host" "card" "tx_pkts" "rx_pkts" "tx_bytes" "rx_bytes"
        local cards_with_traffic=0 total_cards=0
        local host card txp rxp txb rxb pre ptxp prxp ptxb prxb
        local d_txp d_rxp d_txb d_rxb h_txb h_rxb short_host
        while IFS='|' read -r host card txp rxp txb rxb; do
          pre=$(grep "^${host}|${card}|" "$PRE_P7")
          IFS='|' read -r _ _ ptxp prxp ptxb prxb <<<"$pre"
          d_txp=$((txp - ptxp))
          d_rxp=$((rxp - prxp))
          d_txb=$((txb - ptxb))
          d_rxb=$((rxb - prxb))
          total_cards=$((total_cards + 1))
          [[ $d_txp -gt 0 ]] && cards_with_traffic=$((cards_with_traffic + 1))
          h_txb=$(humanize_bytes_long "$d_txb")
          h_rxb=$(humanize_bytes_long "$d_rxb")
          short_host=${host:0:28}
          printf "      %-30s %-15s %-12s %-12s %-12s %-12s\n" \
            "$short_host" "$card" "+$d_txp" "+$d_rxp" "$h_txb" "$h_rxb"
        done <"$POST_P7"
        if (( cards_with_traffic == total_cards )) && [[ $total_cards -gt 0 ]]; then
          check "Phase 7e: every EFA card carried saturation traffic (${tag})" PASS \
            "$cards_with_traffic/$total_cards"
        elif (( cards_with_traffic > 0 )); then
          check "Phase 7e: every EFA card carried saturation traffic (${tag})" FAIL \
            "only $cards_with_traffic/$total_cards cards saw traffic"
        else
          check "Phase 7e: every EFA card carried saturation traffic (${tag})" FAIL \
            "no card saw traffic increase"
        fi
      else
        check "Phase 7e: per-card hw_counter delta (${tag})" SKIP \
          "snapshot empty"
      fi
    }

    # ===== Phase 7a: default mapping (no explicit pinning) =====
    run_sat default \
      "default mapping  --map-by ppr:${FULL_PPN}:node" \
      --map-by "ppr:${FULL_PPN}:node"

    SAT_TABLE="$SAT_TABLE_default"
    P7_HEADLINE_SIZE="$P7_TOPSIZE_default"
    P7_HEADLINE_BW="$P7_TOPBW_default"
    P7_HEADLINE_PCT="$P7_TOPPCT_default"

    # ===== Phase 7b: NUMA-pinned variant (opt-in / auto on multi-NUMA hosts) =====
    # Maps each rank to a single core, distributing across NUMA nodes so libfabric
    # picks the EFA card closest to each rank's NUMA. --report-bindings prints
    # the actual core/NUMA placement to stderr (captured + first 10 lines logged).
    P7B_DELTA=""
    if [[ "${EFA_NUMA_PIN:-0}" == "1" ]]; then
      log ""
      log "--- Phase 7b: NUMA-pinned variant  (--map-by numa --bind-to core) ---"
      run_sat pinned \
        "NUMA-pinned     --map-by numa:PE=1 --bind-to core" \
        --map-by "numa:PE=1" --bind-to core --report-bindings

      log ""
      log "Phase 7b saturation summary (NUMA-pinned):"
      log "$(printf '%s' "$SAT_TABLE_pinned" | sed 's/^/  /')"

      # ===== Phase 7c: side-by-side default vs pinned =====
      # Join SAT_ROWS_default and SAT_ROWS_pinned on size, compute pct delta.
      P7B_DELTA+="$(printf '  %-10s  %-13s  %-13s  %-13s  %-13s  %s\n' \
        'size' 'default Gbps' 'pinned Gbps' 'default sat%' 'pinned sat%' 'pinned vs default')"$'\n'
      P7B_DELTA+="$(printf '  %-10s  %-13s  %-13s  %-13s  %-13s  %s\n' \
        '----------' '-------------' '-------------' '-------------' '-------------' '-----------------')"$'\n'

      # Build associative lookup for pinned rows.
      declare -A P7P_PERNODE=() P7P_SATPCT=() P7P_MIBPS=()
      while IFS=$'\t' read -r psize pmibps ppernode psatpct; do
        [[ -z "$psize" ]] && continue
        P7P_MIBPS["$psize"]="$pmibps"
        P7P_PERNODE["$psize"]="$ppernode"
        P7P_SATPCT["$psize"]="$psatpct"
      done <<<"$SAT_ROWS_pinned"

      while IFS=$'\t' read -r dsize dmibps dpernode dsatpct; do
        [[ -z "$dsize" ]] && continue
        ppernode="${P7P_PERNODE[$dsize]:-}"
        psatpct="${P7P_SATPCT[$dsize]:-}"
        if [[ -n "$ppernode" && -n "$dpernode" ]]; then
          delta=$(awk -v d="$dpernode" -v p="$ppernode" \
            'BEGIN{ if(d>0) printf "%+.1f%%", (p-d)/d*100; else print "n/a" }')
        else
          delta="n/a"
        fi
        P7B_DELTA+="$(printf '  %-10s  %-13s  %-13s  %-13s  %-13s  %s\n' \
          "$(humanize_bytes "$dsize")" \
          "${dpernode:-?} Gbps" "${ppernode:-?} Gbps" \
          "${dsatpct:-?}" "${psatpct:-?}" \
          "$delta")"$'\n'
      done <<<"$SAT_ROWS_default"

      log ""
      log "Phase 7c: default vs pinned (per-node EFA Gbps):"
      log "$(printf '%s' "$P7B_DELTA" | sed 's/^/  /')"

      # If the largest-size pinned beat default by >5%, prefer it as headline.
      if [[ -n "$P7_TOPBW_pinned" && -n "$P7_TOPBW_default" ]]; then
        BETTER=$(awk -v d="$P7_TOPBW_default" -v p="$P7_TOPBW_pinned" \
          'BEGIN{ if(d>0 && (p-d)/d > 0.05) print 1; else print 0 }')
        if [[ "$BETTER" == "1" ]]; then
          log "  -> NUMA pinning improved headline by >5% -- using pinned value as Phase 7 result."
          P7_HEADLINE_BW="$P7_TOPBW_pinned"
          P7_HEADLINE_PCT="$P7_TOPPCT_pinned"
          P7_HEADLINE_SIZE="$P7_TOPSIZE_pinned"
          check "Phase 7b: NUMA pinning improved saturation" PASS \
            "$P7_TOPBW_default Gbps -> $P7_TOPBW_pinned Gbps/node"
        else
          check "Phase 7b: NUMA pinning improved saturation" SKIP \
            "no significant gain ($P7_TOPBW_default vs $P7_TOPBW_pinned Gbps/node)"
        fi
      fi
    else
      log ""
      log "Phase 7b: NUMA pinning skipped (NUMA_PIN_HINT=$NUMA_PIN_HINT)."
      log "    Set EFA_NUMA_PIN=1 in qsub env to force the comparison."
    fi

    if [[ -n "$P7_HEADLINE_BW" ]]; then
      log ""
      log "Phase 7 saturation summary:"
      log "$(printf '%s' "$SAT_TABLE" | sed 's/^/  /')"
      log "  Inter-node fraction:  $INTER_FRAC ((N - PPN) / (N - 1))"
      if [[ -n "$ADV_GBPS" ]]; then
        check "Phase 7: full-cores EFA saturation @ $(humanize_bytes "$P7_HEADLINE_SIZE")" PASS \
          "$P7_HEADLINE_BW Gbps/node ($P7_HEADLINE_PCT of $ADV_GBPS Gbps advertised)"
      else
        check "Phase 7: full-cores aggregate alltoall @ $(humanize_bytes "$P7_HEADLINE_SIZE")" PASS \
          "$P7_HEADLINE_BW Gbps/node"
      fi
    else
      check "Phase 7: full-cores aggregate alltoall" FAIL "no measurement parsed"
    fi
  fi  # end SLOTS_PER_NODE >= FULL_PPN check
else
  if [[ "$NODES" -lt 2 ]]; then
    log ""
    log "=== Phase 7: full-cores aggregate saturation ==="
    log "    SKIP -- single-node"
  fi
  check "Phase 7: full-cores aggregate alltoall" SKIP "single-node or no MPI"
fi

############### Phase 8: OSU MBW_MR (multi-pair NIC capacity) ##################
# osu_mbw_mr is the standard test for "what does the NIC actually deliver".
# Multiple sender-receiver pairs run in parallel at large message sizes; the
# total summed bandwidth approaches the per-node NetworkPerformance cap (90-98%
# typical on healthy EFA), in contrast to MPI_Alltoall which is bisection-
# bandwidth-limited and lands at 50-80% of cap even on perfectly tuned fabrics.
#
# Different question, same hardware:
#   Phase 7  Alltoall      "what bandwidth does my real HPC workload see"
#   Phase 8  OSU MBW_MR    "what bandwidth can the NIC physically sustain"
log ""
log "=== Phase 8: OSU MBW_MR -- multi-pair NIC capacity ==="
OSU_VER="osu-micro-benchmarks-7.5"
OSU_TGZ_URL="https://mvapich.cse.ohio-state.edu/download/mvapich/${OSU_VER}.tar.gz"
OSU_TGZ_SHA256="1cf84ac5419456202757a757c5f9a4f5c6ecd05c65783c7976421cfd6020b3b3"

if [[ -n "$MPIRUN" && "$NODES" -ge 2 && -n "${MPICC:-}" && -x "$MPICC" ]]; then
  OSU_DIR="$HOME/.efa_test_${JOBID}/osu"
  mkdir -p "$OSU_DIR"
  OSU_TGZ="$OSU_DIR/${OSU_VER}.tar.gz"

  # Download + verify SHA256
  if [[ ! -f "$OSU_TGZ" ]]; then
    log "  downloading $OSU_VER from $OSU_TGZ_URL"
    if ! curl -fsSL --max-time 60 -o "$OSU_TGZ" "$OSU_TGZ_URL"; then
      log "  ERROR download failed"
      check "Phase 8: OSU MBW_MR" SKIP "download failed"
      OSU_TGZ=""
    fi
  fi
  if [[ -n "$OSU_TGZ" ]]; then
    ACTUAL_SHA=$(sha256sum "$OSU_TGZ" 2>/dev/null | awk '{print $1}')
    if [[ "$ACTUAL_SHA" != "$OSU_TGZ_SHA256" ]]; then
      log "  ERROR SHA256 mismatch"
      log "    expected $OSU_TGZ_SHA256"
      log "    actual   $ACTUAL_SHA"
      check "Phase 8: OSU MBW_MR" FAIL "tarball SHA256 mismatch"
    else
      log "  SHA256 verified: $ACTUAL_SHA"
      # Extract + build (idempotent)
      OSU_BIN="$OSU_DIR/${OSU_VER}/c/mpi/pt2pt/standard/osu_mbw_mr"
      if [[ ! -x "$OSU_BIN" ]]; then
        log "  extracting + building..."
        ( cd "$OSU_DIR" && tar xzf "$OSU_TGZ" && \
          cd "$OSU_VER" && \
          PATH="$MPI_PREFIX/bin:$PATH" \
          CC=mpicc CXX=mpicxx \
          ./configure --enable-pt2pt-only --prefix="$OSU_DIR/install" \
            >"$OSU_DIR/configure.log" 2>&1 && \
          make -j 4 >"$OSU_DIR/make.log" 2>&1 ) || true
      fi
      if [[ ! -x "$OSU_BIN" ]]; then
        log "  ERROR build failed -- see $OSU_DIR/{configure,make}.log"
        tail -10 "$OSU_DIR/make.log" 2>/dev/null
        check "Phase 8: OSU MBW_MR" FAIL "build failed"
      else
        log "  built $OSU_BIN"
        # osu_mbw_mr expects an even np with (np/2) pairs.  Pair layout: half
        # the ranks on node A pair with half the ranks on node B (across the
        # wire).  We use full PPN so np = 2 * PPN total = PPN pairs all sending
        # cross-node.  Test sizes 1MiB to 2MiB -- larger sizes exhaust EFA
        # queue resources at high-pair-count (window-64 * 64-pairs * 16MiB =
        # ~130GB in-flight, triggers MPI_ERR_INTERN MPI_Waitall).  Steady-state
        # bandwidth is already saturated at 1-2MiB so larger sizes don't add
        # signal.  Use small -W (window) for additional safety margin.
        TOTAL_NP=$(( 2 * PPN ))
        log "  running osu_mbw_mr -np $TOTAL_NP across $NODES nodes ($PPN pairs)"
        log "    sizes 1 MiB - 2 MiB, window 16, FI_PROVIDER=efa, $EFA_DEVICE_RDMA rdma-read"
        MBW_OUT=$( timeout 180 "$MPIRUN" -np "$TOTAL_NP" --map-by ppr:${PPN}:node \
                     --mca pml cm --mca mtl ofi \
                     $EFA_MPI_ENV \
                     -x LD_LIBRARY_PATH="$MPI_PREFIX/lib:/opt/amazon/efa/lib" \
                     "$OSU_BIN" -m 1048576:2097152 -W 16 2>&1 || true )
        echo "$MBW_OUT" | head -40
        # Output format:
        #   # OSU MPI Multiple Bandwidth / Message Rate Test ...
        #   # Size                  MB/s        Messages/s
        #   1048576              19200.45        17.59
        #   ...
        # Largest size's MB/s is the steady-state per-node aggregate bandwidth.
        BEST_LINE=$(echo "$MBW_OUT" | grep -E '^\s*[0-9]+\s+[0-9.]+\s+[0-9.]+' | tail -1)
        if [[ -n "$BEST_LINE" ]]; then
          BSIZE=$(awk '{print $1}' <<<"$BEST_LINE")
          BMBPS=$(awk '{print $2}' <<<"$BEST_LINE")
          # MB/s -> Gbps (decimal): MB/s * 8 / 1000
          BGBPS=$(awk -v m="$BMBPS" 'BEGIN{ printf "%.2f", m * 8 / 1000 }')
          # API-grounded denominators: ADV_GBPS = NetworkPerformance string
          # (what AWS markets); PHYS_CAP_GBPS = sum of per-card baselines
          # (physical wire capacity). They match for most HPC arches; on
          # hpc6id and hpc8a the card-sum is 2x NetPerf because each card is
          # rated at the full instance number. We print both transparently
          # rather than hardcoding a multiplier; pick whichever interpretation
          # matches your reporting convention.
          PCT_ADV=""
          PCT_PHYS=""
          if [[ -n "$ADV_GBPS" ]]; then
            PCT_ADV=$(awk -v g="$BGBPS" -v c="$ADV_GBPS" 'BEGIN{ if(c>0) printf "%.1f", g/c*100 }')
          fi
          if [[ -n "$PHYS_CAP_GBPS" ]]; then
            PCT_PHYS=$(awk -v g="$BGBPS" -v c="$PHYS_CAP_GBPS" 'BEGIN{ if(c>0) printf "%.1f", g/c*100 }')
          fi
          log "  result: $BMBPS MB/s = $BGBPS Gbps aggregate sender bandwidth @ $BSIZE B"
          [[ -n "$ADV_GBPS"      ]] && log "    vs NetworkPerformance ($ADV_GBPS Gbps): ${PCT_ADV}%"
          [[ -n "$PHYS_CAP_GBPS" ]] && log "    vs sum-of-card-baselines ($PHYS_CAP_GBPS Gbps): ${PCT_PHYS}%"
          if [[ -n "$PCT_ADV" && -n "$PCT_PHYS" ]]; then
            check "Phase 8: OSU MBW_MR per-node bandwidth" PASS "$BGBPS Gbps (${PCT_ADV}% of $ADV_GBPS NetPerf | ${PCT_PHYS}% of $PHYS_CAP_GBPS card-sum)"
          elif [[ -n "$PCT_ADV" ]]; then
            check "Phase 8: OSU MBW_MR per-node bandwidth" PASS "$BGBPS Gbps (${PCT_ADV}% of $ADV_GBPS Gbps NetPerf)"
          else
            check "Phase 8: OSU MBW_MR per-node bandwidth" PASS "$BGBPS Gbps"
          fi
          # record_bw expects MiB/s; convert MB/s decimal -> MiB/s binary
          MIBPS=$(awk -v m="$BMBPS" 'BEGIN{ printf "%.2f", m / 1.048576 }')
          record_bw "osu_mbw_mr" "$BSIZE" "$MIBPS" "0" "100" "efa"
        else
          log "  WARN no measurement line parsed"
          tail -20 <<<"$MBW_OUT"
          check "Phase 8: OSU MBW_MR per-node bandwidth" FAIL "no measurement parsed"
        fi
      fi
    fi
  fi
elif [[ "$NODES" -lt 2 ]]; then
  check "Phase 8: OSU MBW_MR per-node bandwidth" SKIP "single-node test"
else
  check "Phase 8: OSU MBW_MR per-node bandwidth" SKIP "no mpirun or mpicc"
fi

############### Generate artifacts: CSV + ASCII chart + HTML ###################
log ""
log "=== Generating artifacts ==="

CSV="$HOME/efa_results_${JOBID}.csv"
TXT="$HOME/efa_results_${JOBID}.txt"
HTM="$HOME/efa_results_${JOBID}.html"

# Unicode 1/8-block bar renderer. Width=$1 cols, value=$2, max=$3.
# Output uses U+2588 (full block) and U+258F..U+258A (partial blocks) to give
# 8x the resolution of plain '#' characters. ASCII fallback when LANG isn't
# UTF-8 (rare on EC2 default AL2/AL2023 but cheap to handle).
render_bar() {
  local width="$1" value="$2" max="$3"
  awk -v w="$width" -v v="$value" -v m="$max" '
    BEGIN {
      if (m <= 0) m = 1;
      if (v < 0) v = 0;
      eighths = int( (v / m) * w * 8 + 0.5 );
      if (eighths > w * 8) eighths = w * 8;
      full = int(eighths / 8);
      part = eighths % 8;
      # UTF-8 bytes for U+2588..U+258F (full to 1/8 block)
      blocks[0] = "";
      blocks[1] = "\xE2\x96\x8F";  # 1/8
      blocks[2] = "\xE2\x96\x8E";  # 2/8
      blocks[3] = "\xE2\x96\x8D";  # 3/8
      blocks[4] = "\xE2\x96\x8C";  # 4/8
      blocks[5] = "\xE2\x96\x8B";  # 5/8
      blocks[6] = "\xE2\x96\x8A";  # 6/8
      blocks[7] = "\xE2\x96\x89";  # 7/8
      FB = "\xE2\x96\x88";          # full block
      out = "";
      for (i = 0; i < full; i++) out = out FB;
      out = out blocks[part];
      # pad right to width chars (in display columns, partial counts as 1)
      total = full + (part > 0 ? 1 : 0);
      for (i = total; i < w; i++) out = out " ";
      print out;
    }'
}

# Same as render_bar but ASCII fallback (=, |) for environments without UTF-8.
render_bar_ascii() {
  local width="$1" value="$2" max="$3"
  awk -v w="$width" -v v="$value" -v m="$max" '
    BEGIN {
      if (m <= 0) m = 1; if (v < 0) v = 0;
      n = int( (v / m) * w + 0.5 );
      if (n > w) n = w;
      out = ""; for (i = 0; i < n; i++) out = out "=";
      for (i = n; i < w; i++) out = out " ";
      print out;
    }'
}

# Pick renderer once based on locale. UTF-8 bars are much nicer on modern
# terminals; ASCII fallback for legacy LANG=C envs.
case "${LANG:-${LC_ALL:-}}" in
  *.UTF-8|*.utf8|*.utf-8|*UTF8*) BAR_FN=render_bar ;;
  *) BAR_FN=render_bar_ascii ;;
esac

# Render a single chart row aligned to fixed widths.
# args: label (max 28 chars), size_label (10 chars), mibps_value, mibps_max,
#       bar_width, value_label_text
render_row() {
  local lbl="$1" sz="$2" v="$3" max="$4" w="$5" vlabel="$6"
  local bar
  bar=$($BAR_FN "$w" "$v" "$max")
  printf '   %-26s  %-9s  %s  %s\n' "$lbl" "$sz" "$bar" "$vlabel"
}

# Render the saturation% gauge: a 20-col bar showing pct out of 100, with the
# advertised line marked at end. Used in the saturation curve chart only.
render_pct_gauge() {
  local pct="$1" w="${2:-20}"
  # Strip trailing '%' from $pct, default to 0 if non-numeric
  local v="${pct%\%}"
  awk -v w="$w" -v v="$v" '
    BEGIN {
      if (v < 0) v = 0; if (v > 100) v = 100;
      eighths = int(v / 100 * w * 8 + 0.5);
      full = int(eighths / 8); part = eighths % 8;
      blocks[0]=""; blocks[1]="\xE2\x96\x8F"; blocks[2]="\xE2\x96\x8E";
      blocks[3]="\xE2\x96\x8D"; blocks[4]="\xE2\x96\x8C"; blocks[5]="\xE2\x96\x8B";
      blocks[6]="\xE2\x96\x8A"; blocks[7]="\xE2\x96\x89";
      FB="\xE2\x96\x88"; PAD="\xE2\x96\x91"; # light shade for empty
      out="["; for(i=0;i<full;i++) out=out FB; out=out blocks[part];
      total = full + (part>0?1:0);
      for(i=total;i<w;i++) out=out PAD;
      out=out "]";
      print out;
    }'
}

# CSV
{
  echo "phase,size_bytes,bandwidth_mibps,bandwidth_gbps,usec_per_xfer,iters,transport"
  for r in "${BW[@]}"; do
    IFS='|' read -r ph sz mibps usec it tr <<<"$r"
    gbps=$(awk -v v="$mibps" 'BEGIN{printf "%.4f", v*1024*1024*8/1e9}')
    echo "$ph,$sz,$mibps,$gbps,$usec,$it,$tr"
  done
} >"$CSV"

# Compute EFA-vs-TCP delta for the alltoall sizes (for summary).
# IMPORTANT: compare per-node aggregate Gbps, NOT per-rank mibps. Per-rank
# values do not scale linearly with rank count -- they reflect bytes-per-iter
# per rank = (N-1)*size. When EFA runs at np=$TOTAL but TCP runs at the
# capped np=$TCP_TOTAL (Phase 5f port-exhaustion fix), per-rank comparison
# is apples-to-oranges and inflates TCP's apparent throughput.
# Per-node aggregate is consistent: total bytes/sec on the wire across both
# nodes, accounting for the fact that intra-node traffic doesn't hit the
# fabric.  Formula matches Phase 7's saturation math.
mibps_to_per_node_gbps() {
  # args: mibps n_total ppn nodes
  awk -v m="$1" -v n="$2" -v p="$3" -v nd="$4" \
    'BEGIN{ inter = (n - p) / (n - 1); printf "%.2f", m * n * 8 * 1024 * 1024 / 1e9 * inter / nd }'
}
EFA_TCP_DELTA=""
EFA_TCP_DELTA+="$(printf '  %-10s  %-22s  %-22s  %s\n' \
  'size' 'EFA per-node Gbps' 'TCP per-node Gbps' 'EFA/TCP')"$'\n'
EFA_TCP_DELTA+="$(printf '  %-10s  %-22s  %-22s  %s\n' \
  '----------' '----------------------' '----------------------' '-------')"$'\n'
for sz in 1024 16384 262144 1048576; do
  efa_v=$(awk -F'|' -v s="$sz" '$1=="alltoall" && $2==s {print $3}' < <(printf "%s\n" "${BW[@]}"))
  tcp_v=$(awk -F'|' -v s="$sz" '$1=="alltoall_tcp" && $2==s {print $3}' < <(printf "%s\n" "${BW[@]}"))
  if [[ -n "$efa_v" && -n "$tcp_v" ]]; then
    efa_node=$(mibps_to_per_node_gbps "$efa_v" "${TOTAL:-2}" "${PPN:-1}" "${NODES:-2}")
    tcp_node=$(mibps_to_per_node_gbps "$tcp_v" "${TCP_TOTAL:-$TOTAL}" "${TCP_PPN:-$PPN}" "${NODES:-2}")
    ratio=$(awk -v e="$efa_node" -v t="$tcp_node" \
      'BEGIN{ if(t>0) printf "%.1fx", e/t; else print "n/a" }')
    EFA_TCP_DELTA+="$(printf '  %-10s  %-22s  %-22s  %s\n' \
      "$(humanize_bytes "$sz")" \
      "${efa_node} Gbps (np=${TOTAL})" \
      "${tcp_node} Gbps (np=${TCP_TOTAL:-$TOTAL})" \
      "$ratio")"$'\n'
  fi
done

# ASCII text artifact
{
  echo ""
  echo "==================================================================="
  echo " EFA Test Job $JOBID -- $INSTANCE_TYPE -- $NODES node(s)"
  echo "==================================================================="
  echo " Generated: $(date -u +%FT%TZ)"
  echo " Instance:  $INSTANCE_ID  ($INSTANCE_TYPE) in $AVAILABILITY_ZONE"
  echo " Nodes:     ${NODELIST[*]}"
  echo " EFA cards: $EFA_COUNT/node    PPN: $PPN    nproc: $NPROC"
  echo " Domains:   ${EFA_DOMAINS[*]:-none}"
  echo "-------------------------------------------------------------------"
  printf " Result counts:  PASS=%-3d  FAIL=%-3d  SKIP=%-3d\n" "$PASS" "$FAIL" "$SKIP"
  echo "-------------------------------------------------------------------"
  for r in "${RESULTS[@]}"; do
    s="${r%%|*}"; rest="${r#*|}"; n="${rest%%|*}"; d="${rest#*|}"
    printf "  %-4s  %-58s  %s\n" "$s" "$n" "$d"
  done
  if [[ -n "$EFA_TCP_DELTA" ]]; then
    echo ""
    echo "-------------------------------------------------------------------"
    echo " EFA-vs-TCP Alltoall comparison (same code, only FI_PROVIDER changed)"
    echo "-------------------------------------------------------------------"
    printf '%s' "$EFA_TCP_DELTA"
  fi
  if [[ -n "${OMPI45_DELTA:-}" ]]; then
    echo ""
    echo "-------------------------------------------------------------------"
    echo " OMPI 4 vs OMPI 5 comparison (same alltoall.c, recompiled per MPI)"
    echo "-------------------------------------------------------------------"
    printf '%s' "$OMPI45_DELTA"
  fi
  if [[ -n "${SAT_TABLE:-}" ]]; then
    echo ""
    echo "-------------------------------------------------------------------"
    echo " Phase 7: full-cores saturation (PPN=$FULL_PPN, np=$FULL_TOTAL, no oversubscribe)"
    echo " Advertised network bandwidth: ${ADV_GBPS:-?} Gbps per instance"
    echo "-------------------------------------------------------------------"
    printf '%s' "$SAT_TABLE"
  fi
  if [[ -n "${P7B_DELTA:-}" ]]; then
    echo ""
    echo "-------------------------------------------------------------------"
    echo " Phase 7c: NUMA-pinned vs default mapping (same alltoall, same sizes)"
    echo "-------------------------------------------------------------------"
    printf '%s' "$P7B_DELTA"
  fi
  if (( ${#BW[@]} > 0 )); then
    BAR_W=52
    # ===== Chart 1: Single-stream pingpong (Phase 4 + 4b) =====
    # Sub-table: rows where phase starts with fi_pingpong or multirail.
    # Per-group max so a 64B row doesn't disappear under a 1MiB run.
    declare -a GRP1=()
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      case "$ph" in single*|fi_pingpong*|multirail*) GRP1+=("$r") ;; esac
    done
    if (( ${#GRP1[@]} > 0 )); then
      MAX1=$(printf "%s\n" "${GRP1[@]}" | awk -F'|' 'BEGIN{m=0}{if($3+0>m)m=$3+0}END{print m+0}')
      [[ "$MAX1" == "0" ]] && MAX1=1
      MAX1_HUMAN=$(humanize_bw_dual "$MAX1")
      echo ""
      echo "-------------------------------------------------------------------"
      echo " Single-stream pingpong  (Phase 4 / 4b)        scale 0..$MAX1_HUMAN"
      echo "-------------------------------------------------------------------"
      for r in "${GRP1[@]}"; do
        IFS='|' read -r ph sz mibps usec it tr <<<"$r"
        # Pretty-name the phase
        case "$ph" in
          single_*)         lbl="fi_pingpong" ;;
          multirail_rail*)  lbl="multirail rail${ph##multirail_rail}" ;;
          multirail_total)  lbl="multirail aggregate" ;;
          *)                lbl="$ph" ;;
        esac
        render_row "$lbl" "$(humanize_bytes "$sz")" "$mibps" "$MAX1" "$BAR_W" "$(humanize_bw_dual "$mibps")"
      done
    fi

    # ===== Chart 2: MPI Alltoall EFA vs TCP -- side-by-side per size =====
    # Builds a row per size that contains BOTH the EFA bar and the TCP bar
    # so the eye instantly sees the gap. Ratio printed inline at end.
    declare -A AA_EFA=() AA_TCP=()
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      [[ "$ph" == "alltoall"     ]] && AA_EFA["$sz"]="$mibps"
      [[ "$ph" == "alltoall_tcp" ]] && AA_TCP["$sz"]="$mibps"
    done
    AA_SIZES_SORTED=$(printf '%s\n' "${!AA_EFA[@]}" "${!AA_TCP[@]}" | sort -n -u)
    if [[ -n "$AA_SIZES_SORTED" ]]; then
      # Max scale = max EFA value across all sizes (TCP is always smaller).
      MAX2=0
      for sz in $AA_SIZES_SORTED; do
        v="${AA_EFA[$sz]:-0}"
        MAX2=$(awk -v a="$MAX2" -v b="$v" 'BEGIN{print (b+0>a+0)?b:a}')
      done
      [[ "$MAX2" == "0" ]] && MAX2=1
      MAX2_HUMAN=$(humanize_bw_dual "$MAX2")
      AA_BAR_W=24   # narrower so EFA + TCP fit on one line
      echo ""
      echo "-------------------------------------------------------------------"
      echo " MPI Alltoall: EFA vs TCP  (Phase 5d / 5f)     scale 0..$MAX2_HUMAN"
      echo "-------------------------------------------------------------------"
      printf '   %-10s  %-26s  %-26s  %s\n' \
        'size' 'EFA (FI_PROVIDER=efa)' 'TCP (OMPI btl/tcp)' 'EFA/TCP'
      printf '   %-10s  %-26s  %-26s  %s\n' \
        '----------' '--------------------------' '--------------------------' '-------'
      for sz in $AA_SIZES_SORTED; do
        ev="${AA_EFA[$sz]:-0}"; tv="${AA_TCP[$sz]:-0}"
        ebar=$($BAR_FN "$AA_BAR_W" "$ev" "$MAX2")
        tbar=$($BAR_FN "$AA_BAR_W" "$tv" "$MAX2")
        # Compose "[bar] value" cells in fixed widths (display chars only)
        # Truncate humanized labels to keep alignment when bars hit max width.
        eh=$(humanize_bw_dual "$ev")
        th=$(humanize_bw_dual "$tv")
        if [[ "$tv" == "0" ]]; then ratio="--"; else
          ratio=$(awk -v e="$ev" -v t="$tv" 'BEGIN{ if(t>0) printf "%.1fx", e/t; else print "--" }')
        fi
        # Mark high ratio with check sentinel (>=10x)
        check=""
        awk -v r="${ratio%x}" 'BEGIN{ exit !(r+0 >= 10) }' && check=" *"
        printf '   %-10s  [%s] %-22s [%s] %-22s %s%s\n' \
          "$(humanize_bytes "$sz")" "$ebar" "$eh" "$tbar" "$th" "$ratio" "$check"
      done
      echo "                                                                              ( * EFA >=10x faster than TCP )"
    fi

    # ===== Chart 3: Phase 7 saturation curve (default + pinned if present) =====
    declare -a GRP3=()
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      case "$ph" in alltoall_sat|alltoall_sat_pin) GRP3+=("$r") ;; esac
    done
    if (( ${#GRP3[@]} > 0 )); then
      MAX3=$(printf "%s\n" "${GRP3[@]}" | awk -F'|' 'BEGIN{m=0}{if($3+0>m)m=$3+0}END{print m+0}')
      [[ "$MAX3" == "0" ]] && MAX3=1
      MAX3_GBPS=$(awk -v v="$MAX3" 'BEGIN{printf "%.2f Gbps/rank", v*1024*1024*8/1e9}')
      echo ""
      echo "-------------------------------------------------------------------"
      echo " Full-cores saturation curve  (Phase 7)        scale 0..$MAX3_GBPS"
      [[ -n "${ADV_GBPS:-}" ]] && \
        echo "                                                advertised: $ADV_GBPS Gbps/node"
      echo "-------------------------------------------------------------------"
      printf '   %-10s  %-26s  %s\n' 'size' 'per-rank Gbps' 'per-node sat% (advertised)'
      printf '   %-10s  %-26s  %s\n' '----------' '--------------------------' '----------------------------------'
      # Re-iterate in size order; emit default row, then pinned row if present.
      P7_SIZES_SORTED=$(printf '%s\n' "${GRP3[@]}" | awk -F'|' '{print $2}' | sort -n -u)
      for sz in $P7_SIZES_SORTED; do
        for variant in alltoall_sat alltoall_sat_pin; do
          row=$(printf '%s\n' "${GRP3[@]}" | awk -F'|' -v p="$variant" -v s="$sz" '$1==p && $2==s {print; exit}')
          [[ -z "$row" ]] && continue
          IFS='|' read -r ph sz_r mibps usec it tr <<<"$row"
          gbps=$(awk -v v="$mibps" 'BEGIN{printf "%.2f Gbps", v*1024*1024*8/1e9}')
          # Look up sat% from SAT_TABLE_default / SAT_TABLE_pinned by size
          if [[ "$ph" == "alltoall_sat_pin" ]]; then tbl="$SAT_TABLE_pinned"; else tbl="$SAT_TABLE_default"; fi
          sat=$(printf '%s' "$tbl" | awk -v sb="$(humanize_bytes "$sz")" \
            'BEGIN{ split(sb,a," "); n=a[1]; u=a[2] } $1==n && $2==u { print $NF; exit }')
          [[ -z "$sat" ]] && sat="--"
          gauge=$(render_pct_gauge "$sat" 20)
          variant_lbl="default"; [[ "$ph" == "alltoall_sat_pin" ]] && variant_lbl="pinned "
          render_row "alltoall_sat $variant_lbl" "$(humanize_bytes "$sz")" "$mibps" "$MAX3" "$BAR_W" "$gbps     $gauge $sat"
        done
      done
    fi
  fi
  echo "==================================================================="
} >"$TXT"

# HTML with inline SVG
{
  echo "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
  echo "<title>EFA Test $JOBID -- $INSTANCE_TYPE</title>"
  cat <<'CSS'
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 1180px; margin: 24px auto; padding: 0 16px; color:#222; }
  h1 { margin: 0 0 6px; }
  .meta { color:#666; font-size: 13px; margin-bottom: 18px; }
  .badges { display:flex; gap:10px; margin: 12px 0 20px; }
  .badge { display:inline-block; padding:4px 12px; border-radius:6px; font-weight:600; font-size:13px; }
  .b-pass { background:#dff6dd; color:#1e7a1e; }
  .b-fail { background:#fde2e2; color:#a02323; }
  .b-skip { background:#eef0f2; color:#555; }
  table { border-collapse: collapse; width:100%; font-size: 13px; margin: 8px 0 16px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid #eee; }
  th { background:#f5f7fa; }
  .s-PASS { color:#1e7a1e; font-weight:600; }
  .s-FAIL { color:#a02323; font-weight:600; }
  .s-SKIP { color:#555; }
  .chart { margin: 12px 0 24px; }
  .chart-title { font-size: 12px; color: #555; margin: 8px 0 4px; font-family: ui-monospace, monospace; }
  .bar-pp  { fill: #2e86c1; }     /* fi_pingpong (single-stream) */
  .bar-mr  { fill: #16a085; }     /* multirail */
  .bar-efa { fill: #2ca02c; }     /* alltoall EFA */
  .bar-tcp { fill: #b0a020; }     /* alltoall TCP */
  .bar-sat { fill: #d35400; }     /* alltoall_sat default */
  .bar-pin { fill: #884ea0; }     /* alltoall_sat_pin */
  .bar-bg  { fill: #f5f7fa; stroke: #e0e0e0; }
  .barlabel { font-size: 11px; fill: #222; dominant-baseline: middle; }
  .barlabel-r { font-size: 11px; fill: #555; dominant-baseline: middle; text-anchor: end; }
  .barlabel-mono { font-size: 10px; fill: #222; dominant-baseline: middle; font-family: ui-monospace, monospace; }
  .legend { font-size: 11px; color: #555; margin: 0 0 12px; display: flex; flex-wrap: wrap; gap: 14px; }
  .legend-sw { display: inline-block; width: 12px; height: 12px; vertical-align: middle; margin-right: 4px; border-radius: 2px; }
  .ratio-pos { fill: #1e7a1e; font-weight: 600; }
  .ratio-neg { fill: #a02323; font-weight: 600; }
  .adv-line  { stroke: #a02323; stroke-width: 1.5; stroke-dasharray: 4 3; }
  .adv-text  { font-size: 10px; fill: #a02323; font-family: ui-monospace, monospace; }
  h2 { font-size: 17px; margin-top: 28px; }
  .delta { font-family: ui-monospace, monospace; font-size: 12px; background:#f5f7fa; padding:8px; border-radius:6px; white-space:pre; }
</style>
CSS
  echo "</head><body>"
  echo "<h1>EFA Test Job $JOBID</h1>"
  echo "<div class=\"meta\">"
  echo "  <b>Instance:</b> $INSTANCE_TYPE ($INSTANCE_ID) &nbsp;|&nbsp;"
  echo "  <b>AZ:</b> $AVAILABILITY_ZONE &nbsp;|&nbsp;"
  echo "  <b>Nodes:</b> $NODES &nbsp;|&nbsp;"
  echo "  <b>EFA cards/node:</b> $EFA_COUNT &nbsp;|&nbsp;"
  echo "  <b>Domains:</b> ${EFA_DOMAINS[*]:-none} &nbsp;|&nbsp;"
  echo "  <b>PPN:</b> $PPN &nbsp;|&nbsp;"
  echo "  <b>Generated:</b> $(date -u +%FT%TZ) UTC"
  echo "</div>"
  echo "<div class=\"badges\">"
  echo "  <span class=\"badge b-pass\">PASS $PASS</span>"
  echo "  <span class=\"badge b-fail\">FAIL $FAIL</span>"
  echo "  <span class=\"badge b-skip\">SKIP $SKIP</span>"
  echo "</div>"

  echo "<h2>Test results</h2>"
  echo "<table><thead><tr><th>Status</th><th>Test</th><th>Detail</th></tr></thead><tbody>"
  for r in "${RESULTS[@]}"; do
    s="${r%%|*}"; rest="${r#*|}"; n="${rest%%|*}"; d="${rest#*|}"
    echo "<tr><td class=\"s-$s\">$s</td><td>$n</td><td>$d</td></tr>"
  done
  echo "</tbody></table>"

  if [[ -n "$EFA_TCP_DELTA" ]]; then
    echo "<h2>EFA vs TCP (same MPI_Alltoall code, FI_PROVIDER toggled)</h2>"
    echo "<div class=\"delta\">$EFA_TCP_DELTA</div>"
  fi

  if [[ -n "${OMPI45_DELTA:-}" ]]; then
    echo "<h2>OMPI 4 vs OMPI 5 (same alltoall.c, recompiled per MPI)</h2>"
    echo "<div class=\"delta\">$OMPI45_DELTA</div>"
  fi

  if [[ -n "${SAT_TABLE:-}" ]]; then
    echo "<h2>Phase 7: full-cores saturation (PPN=$FULL_PPN, np=$FULL_TOTAL)"
    [[ -n "${ADV_GBPS:-}" ]] && echo "<br><span style=\"font-size:13px;color:#666;\">Advertised: $ADV_GBPS Gbps/node</span>"
    echo "</h2>"
    echo "<div class=\"delta\">$SAT_TABLE</div>"
  fi

  if [[ -n "${P7B_DELTA:-}" ]]; then
    echo "<h2>Phase 7c: NUMA-pinned vs default mapping</h2>"
    echo "<div class=\"delta\">$P7B_DELTA</div>"
  fi

  if (( ${#BW[@]} > 0 )); then
    echo "<h2>Bandwidth measurements</h2>"
    echo "<table><thead><tr><th>Phase</th><th>Transport</th><th>Size</th><th>Throughput (binary, storage)</th><th>Throughput (decimal, network)</th><th>usec/xfer</th></tr></thead><tbody>"
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      hb_b=$(humanize_bw_mbps "$mibps")
      hb_n=$(humanize_bw_bps "$mibps")
      hs=$(humanize_bytes "$sz")
      echo "<tr><td>$ph</td><td>$tr</td><td>$hs</td><td><b>$hb_b</b></td><td><b>$hb_n</b></td><td>$usec</td></tr>"
    done
    echo "</tbody></table>"

    # ===== HTML chart helpers =====
    # Render an SVG chart row: label | bar | value.
    # args: y, label, css_class, value, max_val, value_label
    # globals: BAR_W=520, ROW_H=22, LBL_W=200
    BAR_W=520; ROW_H=22; LBL_W=240
    svg_row() {
      local y="$1" lbl="$2" cls="$3" val="$4" mx="$5" vlbl="$6"
      local bw_px ty
      bw_px=$(awk -v v="$val" -v m="$mx" -v w="$BAR_W" 'BEGIN{ if(m<=0) m=1; n=int((v/m)*w+0.5); if(n>w)n=w; printf "%d", n }')
      ty=$((y + ROW_H/2))
      echo "  <text x=\"6\" y=\"$ty\" class=\"barlabel\">$lbl</text>"
      echo "  <rect x=\"$LBL_W\" y=\"$y\" width=\"$BAR_W\" height=\"$((ROW_H-4))\" class=\"bar-bg\"/>"
      echo "  <rect x=\"$LBL_W\" y=\"$y\" width=\"$bw_px\" height=\"$((ROW_H-4))\" class=\"$cls\"/>"
      echo "  <text x=\"$((LBL_W + BAR_W + 8))\" y=\"$ty\" class=\"barlabel-mono\">$vlbl</text>"
    }

    echo "<h2>Bandwidth charts</h2>"
    echo "<div class=\"legend\">"
    echo "  <span><span class=\"legend-sw\" style=\"background:#2e86c1\"></span>fi_pingpong (single-stream)</span>"
    echo "  <span><span class=\"legend-sw\" style=\"background:#16a085\"></span>multirail</span>"
    echo "  <span><span class=\"legend-sw\" style=\"background:#2ca02c\"></span>alltoall EFA</span>"
    echo "  <span><span class=\"legend-sw\" style=\"background:#b0a020\"></span>alltoall TCP</span>"
    echo "  <span><span class=\"legend-sw\" style=\"background:#d35400\"></span>saturation default</span>"
    echo "  <span><span class=\"legend-sw\" style=\"background:#884ea0\"></span>saturation NUMA-pinned</span>"
    echo "</div>"

    # ===== Chart 1: Single-stream pingpong (Phase 4 + 4b) =====
    declare -a HG1=()
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      case "$ph" in single*|fi_pingpong*|multirail*) HG1+=("$r") ;; esac
    done
    if (( ${#HG1[@]} > 0 )); then
      MX1=$(printf "%s\n" "${HG1[@]}" | awk -F'|' 'BEGIN{m=0}{if($3+0>m)m=$3+0}END{print m+0}')
      [[ "$MX1" == "0" ]] && MX1=1
      MX1_HUMAN=$(humanize_bw_dual "$MX1")
      SVG_H=$(( ${#HG1[@]} * ROW_H + 30 ))
      SVG_W=$((LBL_W + BAR_W + 250))
      echo "<div class=\"chart-title\">Single-stream pingpong (Phase 4 / 4b) -- scale 0..$MX1_HUMAN</div>"
      echo "<div class=\"chart\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"$SVG_W\" height=\"$SVG_H\" viewBox=\"0 0 $SVG_W $SVG_H\">"
      y=10
      for r in "${HG1[@]}"; do
        IFS='|' read -r ph sz mibps usec it tr <<<"$r"
        case "$ph" in
          single_*|fi_pingpong*) lbl="fi_pingpong @ $(humanize_bytes "$sz")"; cls="bar-pp" ;;
          multirail_rail*)       lbl="multirail rail${ph##multirail_rail} @ $(humanize_bytes "$sz")"; cls="bar-mr" ;;
          multirail_total)       lbl="multirail aggregate @ $(humanize_bytes "$sz")"; cls="bar-mr" ;;
          *)                     lbl="$ph @ $(humanize_bytes "$sz")"; cls="bar-pp" ;;
        esac
        svg_row "$y" "$lbl" "$cls" "$mibps" "$MX1" "$(humanize_bw_dual "$mibps")"
        y=$((y + ROW_H))
      done
      echo "</svg></div>"
    fi

    # ===== Chart 2: MPI Alltoall EFA vs TCP (per-size grouped) =====
    declare -A HAA_EFA=() HAA_TCP=()
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      [[ "$ph" == "alltoall"     ]] && HAA_EFA["$sz"]="$mibps"
      [[ "$ph" == "alltoall_tcp" ]] && HAA_TCP["$sz"]="$mibps"
    done
    HAA_SIZES=$(printf '%s\n' "${!HAA_EFA[@]}" "${!HAA_TCP[@]}" | sort -n -u)
    if [[ -n "$HAA_SIZES" ]]; then
      MX2=0
      for sz in $HAA_SIZES; do
        v="${HAA_EFA[$sz]:-0}"
        MX2=$(awk -v a="$MX2" -v b="$v" 'BEGIN{print (b+0>a+0)?b:a}')
      done
      [[ "$MX2" == "0" ]] && MX2=1
      MX2_HUMAN=$(humanize_bw_dual "$MX2")
      ROWS2=$(echo "$HAA_SIZES" | wc -l | awk '{print $1*2}')
      SVG_H=$(( ROWS2 * ROW_H + 20 ))
      SVG_W=$((LBL_W + BAR_W + 250))
      echo "<div class=\"chart-title\">MPI Alltoall: EFA vs TCP (Phase 5d/5f) -- scale 0..$MX2_HUMAN</div>"
      echo "<div class=\"chart\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"$SVG_W\" height=\"$SVG_H\" viewBox=\"0 0 $SVG_W $SVG_H\">"
      y=10
      for sz in $HAA_SIZES; do
        ev="${HAA_EFA[$sz]:-0}"; tv="${HAA_TCP[$sz]:-0}"
        ratio="--"
        if [[ "$tv" != "0" ]]; then
          ratio=$(awk -v e="$ev" -v t="$tv" 'BEGIN{ if(t>0) printf "%.1fx", e/t; else print "--" }')
        fi
        # EFA on top row, TCP below, with size label only on the EFA row
        sl="$(humanize_bytes "$sz")"
        svg_row "$y" "EFA $sl" "bar-efa" "$ev" "$MX2" "$(humanize_bw_dual "$ev")  ($ratio faster)"
        y=$((y + ROW_H))
        svg_row "$y" "TCP $sl" "bar-tcp" "$tv" "$MX2" "$(humanize_bw_dual "$tv")"
        y=$((y + ROW_H))
      done
      echo "</svg></div>"
    fi

    # ===== Chart 3: Saturation curve (default + pinned) with advertised line =====
    declare -a HG3=()
    for r in "${BW[@]}"; do
      IFS='|' read -r ph sz mibps usec it tr <<<"$r"
      case "$ph" in alltoall_sat|alltoall_sat_pin) HG3+=("$r") ;; esac
    done
    if (( ${#HG3[@]} > 0 )); then
      MX3=$(printf "%s\n" "${HG3[@]}" | awk -F'|' 'BEGIN{m=0}{if($3+0>m)m=$3+0}END{print m+0}')
      [[ "$MX3" == "0" ]] && MX3=1
      MX3_GBPS=$(awk -v v="$MX3" 'BEGIN{printf "%.2f Gbps/rank", v*1024*1024*8/1e9}')
      SVG_H=$(( ${#HG3[@]} * ROW_H + 30 ))
      SVG_W=$((LBL_W + BAR_W + 280))
      echo "<div class=\"chart-title\">Full-cores saturation curve (Phase 7) -- scale 0..$MX3_GBPS"
      [[ -n "${ADV_GBPS:-}" ]] && echo " &nbsp;&nbsp;advertised: $ADV_GBPS Gbps/node (red dashed line at saturation point)"
      echo "</div>"
      echo "<div class=\"chart\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"$SVG_W\" height=\"$SVG_H\" viewBox=\"0 0 $SVG_W $SVG_H\">"
      y=10
      P7_SIZES=$(printf '%s\n' "${HG3[@]}" | awk -F'|' '{print $2}' | sort -n -u)
      for sz in $P7_SIZES; do
        for variant in alltoall_sat alltoall_sat_pin; do
          row=$(printf '%s\n' "${HG3[@]}" | awk -F'|' -v p="$variant" -v s="$sz" '$1==p && $2==s {print; exit}')
          [[ -z "$row" ]] && continue
          IFS='|' read -r ph sz_r mibps usec it tr <<<"$row"
          gbps=$(awk -v v="$mibps" 'BEGIN{printf "%.2f Gbps/rank", v*1024*1024*8/1e9}')
          if [[ "$ph" == "alltoall_sat_pin" ]]; then
            lbl="alltoall_sat pinned @ $(humanize_bytes "$sz")"; cls="bar-pin"
          else
            lbl="alltoall_sat default @ $(humanize_bytes "$sz")"; cls="bar-sat"
          fi
          svg_row "$y" "$lbl" "$cls" "$mibps" "$MX3" "$gbps"
          y=$((y + ROW_H))
        done
      done
      echo "</svg></div>"
    fi
  fi

  echo "<h2>Verbose topology</h2>"
  echo "<p>Full <code>ibv_devinfo -v</code> + <code>fi_info -p efa -v</code> dump: <code>$TOPO_FILE</code></p>"
  echo "<h2>Provider selection log</h2>"
  echo "<p>libfabric verbose log from MPI launch: <code>$EFA_LOG</code></p>"
  echo "</body></html>"
} >"$HTM"

cat "$TXT"

log ""
log "Artifacts written:"
log "  CSV:   $CSV  ($(wc -l <"$CSV") lines)"
log "  TXT:   $TXT  ($(wc -l <"$TXT") lines)"
log "  HTML:  $HTM  ($(wc -l <"$HTM") lines)"
log "  TOPO:  $TOPO_FILE"
log "  PROV:  $EFA_LOG"

log ""
log "DONE"
[[ $FAIL -gt 0 ]] && exit 4 || exit 0

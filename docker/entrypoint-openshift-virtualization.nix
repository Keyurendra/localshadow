{ pkgs }:

pkgs.writeShellScriptBin "entrypoint-openshift" ''
  set -euo pipefail

  # fix for openshift
  ${pkgs.coreutils}/bin/chmod 755 /

  dev="$1"; shift
  mountpoint=/mnt/accuknox
  skipMalwareScan=false

  if [[ -z "$ARTIFACT_API_ENDPOINT" ]]; then
    echo "env variable ARTIFACT_API_ENDPOINT not set"
    exit 1
  fi

  if [[ -z "$ARTIFACT_API_TENANT_ID" ]]; then
    echo "env variable ARTIFACT_API_TENANT_ID not set"
    exit 1
  fi

  if [[ -z "$ARTIFACT_API_LABEL" ]]; then
    echo "env variable ARTIFACT_API_LABEL not set"
    exit 1
  fi

  if [[ "$SKIP_MALWARE_SCAN" == "true" || "$SKIP_MALWARE_SCAN" == "1" ]]; then
    skipMalwareScan=true
  fi

  ${pkgs.coreutils}/bin/mkdir -p "$mountpoint"

  tmp_mounts=()

  cleanup() {
    echo "[*] Cleaning up"
    for m in "''${tmp_mounts[@]}"; do
      ${pkgs.util-linux}/bin/umount -l "$m" >/dev/null 2>&1 || true
      ${pkgs.coreutils}/bin/rmdir "$m" >/dev/null 2>&1 || true
    done
    ${pkgs.util-linux}/bin/umount "$mountpoint" >/dev/null 2>&1 || true
    ${pkgs.multipath-tools}/bin/kpartx -dv "$dev" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  if [[ $skipMalwareScan == false ]]; then
    echo "[*] Downloading ClamAV DB"
    ${pkgs.clamav}/bin/freshclam
  fi

  echo "[*] Downloading Trivy DB"
  export TRIVY_CACHE_DIR=/var/lib/accuknox-omni
  ${pkgs.trivy}/bin/trivy rootfs --no-progress --download-db-only
  ${pkgs.trivy}/bin/trivy rootfs --no-progress --download-java-db-only

  echo "[*] Downloading MSRC DB"
  omni db download msrc

  echo "[*] Creating device maps for $dev"
  ${pkgs.multipath-tools}/bin/kpartx -av "$dev" >/dev/null

  echo "[*] Collecting partition candidates"
  base=$(${pkgs.coreutils}/bin/basename "$dev")
  candidates=()

  for p in /dev/mapper/''${base}*; do
    [[ -e "$p" ]] && candidates+=("$p")
  done
  candidates=( $(printf "%s\n" "''${candidates[@]}" | ${pkgs.gawk}/bin/awk '!seen[$0]++') )

  if [[ "''${#candidates[@]}" -eq 0 ]]; then
    echo "[!] No partitions found"
    exit 1
  fi

  get_fstype() {
    ${pkgs.util-linux}/bin/blkid -o value -s TYPE "$1" 2>/dev/null || echo ""
  }

  score_partition() {
    local p="$1"
    local score=0
    local tmpdir=$(${pkgs.coreutils}/bin/mktemp -d /tmp/probe.XXXX)
    tmp_mounts+=("$tmpdir")

    if ! ${pkgs.util-linux}/bin/mount -o ro,noload "$p" "$tmpdir" >/dev/null 2>&1; then
      echo 0; return
    fi

    [[ -f "$tmpdir/etc/os-release" ]] && score=$((score + 50))
    [[ -d "$tmpdir/etc" ]] && score=$((score + 20))
    [[ -d "$tmpdir/usr" ]] && score=$((score + 15))
    [[ -d "$tmpdir/bin" ]] && score=$((score + 10))
    [[ -d "$tmpdir/sbin" ]] && score=$((score + 10))
    [[ -d "$tmpdir/Windows/System32" ]] && score=$((score + 40))
    [[ -f "$tmpdir/etc/fstab" ]] && score=$((score + 10))
    [[ -f "$tmpdir/etc/passwd" ]] && score=$((score + 10))

    size=$(${pkgs.util-linux}/bin/lsblk -b -dn -o SIZE "$p" 2>/dev/null || echo 0)
    (( size < 104857600 )) && score=$((score - 30))

    echo "$score"
  }

  best=""
  bestscore=-99999

  echo "[*] Probing partitions..."
  for part in "''${candidates[@]}"; do
    fstype=$(get_fstype "$part")
    [[ "$fstype" =~ ^(swap|iso9660)$ ]] && continue

    sc=$(score_partition "$part" || echo 0)
    echo "[*] $part ($fstype) => score=$sc"
    if (( sc > bestscore )); then
      bestscore=$sc
      best="$part"
    fi
  done

  for m in "''${tmp_mounts[@]}"; do
    ${pkgs.util-linux}/bin/umount "$m" >/dev/null 2>&1 || true
    ${pkgs.coreutils}/bin/rmdir "$m" >/dev/null 2>&1 || true
  done
  tmp_mounts=()

  if [[ -z "$best" || "$bestscore" -lt 20 ]]; then
    echo "[*] Low-confidence; picking largest filesystem partition"
    best=""
    largest_size=0
    for part in "''${candidates[@]}"; do
      fstype=$(get_fstype "$part")
      [[ "$fstype" =~ ^(swap|iso9660)$ ]] && continue
      size=$(${pkgs.util-linux}/bin/lsblk -b -dn -o SIZE "$part" 2>/dev/null || echo 0)
      (( size > largest_size )) && { largest_size=$size; best="$part"; }
    done
  fi

  if [[ -z "$best" ]]; then
    echo "[!] Could not detect root partition"
    exit 1
  fi

  echo "[*] Mounting $best to $mountpoint (ro)"
  ${pkgs.util-linux}/bin/mount -o ro "$best" "$mountpoint"

  echo "[*] Starting Omni"
  omni openshift scan "$mountpoint" \
    --artifact-endpoint "$ARTIFACT_API_ENDPOINT" \
    --tenant-id "$ARTIFACT_API_TENANT_ID" \
    --skip-malware-scan "$skipMalwareScan" \
    --artifact-label "$ARTIFACT_API_LABEL" "$@"
''

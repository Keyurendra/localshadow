#!/usr/bin/env bash

set -euo pipefail

OMNI_VERSION="${OMNI_VERSION:-latest}"
OMNI_URL="${OMNI_URL:-""}"
OMNI_INSTALL_PATH=${OMNI_INSTALL_PATH:-/usr/local/bin/}
OMNI_INSTALL_SYSTEMD_DIR="${OMNI_INSTALL_SYSTEMD_DIR:-/etc/systemd/system/}"
OMNI_SKIP_DOWNLOAD="${OMNI_SKIP_DOWNLOAD:-false}"
OMNI_ARTIFACT_API_TOKEN="${OMNI_ARTIFACT_API_TOKEN:-""}"
OMNI_TRIGGER_IMMEDIATELY="${OMNI_RUN_IMMEDIATELY:-true}"
OMNI_SKIP_DB_DOWNLOAD="${OMNI_SKIP_DB_DOWNLOAD:-false}"
OMNI_VULN_DB_REPOSITORY=${OMNI_VULN_DB_REPOSITORY:-"ghcr.io/aquasecurity/trivy-db"}
OMNI_JAVA_DB_REPOSITORY=${OMNI_JAVA_DB_REPOSITORY:-"ghcr.io/aquasecurity/trivy-java-db"}
OMNI_HOME_DIR="${OMNI_HOME_DIR:-/var/lib/accuknox-omni/}"
OMNI_SKIP_MALWARE_SCAN="${OMNI_SKIP_MALWARE_SCAN:-true}"
OMNI_MAX_MEMORY="${OMNI_MAX_MEMORY:-2G}"
OMNI_CPU_QUOTA="${OMNI_CPU_QUOTA:-10%}"

info() {
    echo '[INFO]' "$@"
}

warn() {
    echo '[WARN]' "$@" >&2
}

fatal() {
    echo '[ERROR]' "$@" >&2
    exit 1
}

# --- add quotes to command arguments ---
quote() {
    for arg in "$@"; do
        printf "%s\n" "$arg" | sed "s/'/'\\\\''/g;1s/^/'/;\$s/\$/'/"
    done
}

# --- add indentation and trailing slash to quoted args ---
quote_indent() {
    local i=1 last=$#
    for arg in "$@"; do
        if (( i == 1 )); then
            printf ' \\\n'
        fi
        if (( i < last )); then
            printf '\t%s \\\n' "$(quote "$arg")"
        else
            printf '\t%s\n' "$(quote "$arg")"
        fi
        ((i++))
    done
}

filepath_join() {
    local path=""
    for part in "$@"; do
        path="${path%/}"
        if [[ -n "$path" && "$part" == /* ]]; then
            part="${part#/}"
        fi
        path="${path:+$path/}$part"
    done
    echo "$path"
}

# --- helper function to download file using curl/wget ---
download() {
    [[ $# -eq 2 ]] || fatal 'Download needs exactly 2 arguments'

    # Disable exit-on-error so we can do custom error messages on failure
    set +e

    # Default to a failure status
    status=1

    case $DOWNLOADER in
        curl)
            curl -o "$1" -sfL "$2"
            status=$?
            ;;
        wget)
            wget -qO "$1" "$2"
            status=$?
            ;;
        *)
	    # Enable exit-on-error for fatal to execute
	    set -e
            fatal "Incorrect executable '$DOWNLOADER'"
            ;;
    esac

    # Re-enable exit-on-error
    set -e

    # Abort if download command failed
    [[ $status -eq 0 ]] || fatal 'Download failed'
}

# --- fatal if no systemd ---
verify_systemd() {
    if [[ -x /bin/systemctl ]] || type systemctl > /dev/null 2>&1; then
        return
    fi
    fatal 'Can not find systemd to use as a process supervisor for omni'
}

# --- ensures $OMNI_URL begins with http(s)://, exiting fatally otherwise ---
verify_omni_url() {
    case "${OMNI_URL}" in
        http://*)
            ;;
        https://*)
            ;;
        *)
            fatal "Only http:// and https:// URLs are supported for OMNI_URL (have ${OMNI_URL})"
            ;;
    esac
}

# --- verify an executable omni binary is installed ---
verify_omni_is_executable() {
    if [[ ! -x ${OMNI_BIN_PATH} ]]; then
        fatal "Executable omni binary not found at ${OMNI_BIN_PATH}"
    fi
}

# --- verify existence of network downloader executable ---
setup_verify_downloader() {
    # Return failure if it doesn't exist or is no executable
    [[ -x "$(command -v "$1")" ]] || return 1

    # Set verified executable as our downloader program and return success
    DOWNLOADER=$1
    return 0
}

# --- fatal if architecture not supported ---
setup_verify_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        amd64)
            ARCH=amd64
            ;;
        x86_64)
            ARCH=amd64
            ;;
        arm64)
            ARCH=arm64
            ;;
        aarch64)
            ARCH=arm64
            ;;
        *)
            fatal "Unsupported architecture $ARCH"
    esac
    info "Host architecture $ARCH"
}

setup_env() {
    # --- use sudo if we are not already root ---
    SUDO=sudo
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=
    fi

    setup_verify_downloader curl || verify_downloader wget || fatal 'Can not find curl or wget for downloading files'
    setup_verify_arch

    if [[ -z "$OMNI_URL" ]]; then
        OMNI_URL="https://accuknox-omni.s3.us-east-1.amazonaws.com/${OMNI_VERSION}/omni-linux-${ARCH}"
    fi

    if [[ -z $OMNI_ARTIFACT_API_TOKEN ]]; then
        read -rsp "Enter artifact API token: " OMNI_ARTIFACT_API_TOKEN
        echo
        if [[ -z $OMNI_ARTIFACT_API_TOKEN ]]; then
            fatal "OMNI_ARTIFACT_API_TOKEN cannot be empty"
        fi
    fi

    OMNI_BIN_PATH="$(filepath_join "$OMNI_INSTALL_PATH" omni)"
    DB_DOWNLOAD_CMD_EXEC="db download vuln$(quote_indent \
        --vuln-db-repository=${OMNI_VULN_DB_REPOSITORY} \
        --java-db-repository=${OMNI_JAVA_DB_REPOSITORY} \
        --destination="${OMNI_HOME_DIR}")"
    AGENT_CMD_EXEC="agent scan$(quote_indent "$@")"
    if [[ $OMNI_SKIP_MALWARE_SCAN == true || $OMNI_SKIP_MALWARE_SCAN == 1 ]]; then
        AGENT_CMD_EXEC="$AGENT_CMD_EXEC --skip-malware-scan"
    fi
    FILE_OMNI_SERVICE="$(filepath_join "$OMNI_INSTALL_SYSTEMD_DIR" omni.service)"
    FILE_OMNI_TIMER="$(filepath_join "$OMNI_INSTALL_SYSTEMD_DIR" omni.timer)"
    FILE_UNINSTALL_SCRIPT="$(filepath_join "$OMNI_INSTALL_PATH" omni-uninstall.sh)"
}

# --- create temporary directory and cleanup when done ---
setup_tmp() {
    TMP_DIR=$(mktemp -d -t omni-install.XXXXXXXXXX)
    TMP_BIN=${TMP_DIR}/omni.bin
    cleanup() {
        code=$?
        set +e
        trap - EXIT
        rm -rf "${TMP_DIR}"
        exit $code
    }
    trap cleanup INT EXIT
}

setup_token() {
    $SUDO mkdir -p "$OMNI_HOME_DIR"
    tokenFile="$(filepath_join "$OMNI_HOME_DIR" artifact.tok)"
    info "Saving token at $tokenFile"
    echo "$OMNI_ARTIFACT_API_TOKEN" | $SUDO tee "$tokenFile" >/dev/null
    $SUDO chown -R root:root "$OMNI_HOME_DIR"
    $SUDO chmod 600 "$tokenFile"
}

download_binary() {
    info "Downloading binary from ${OMNI_URL}"
    download "${TMP_BIN}" "${OMNI_URL}"

    info "Install binary ${OMNI_URL} to ${OMNI_BIN_PATH}"
    $SUDO mkdir -p "${OMNI_INSTALL_PATH}"
    $SUDO mv "${TMP_BIN}" "${OMNI_BIN_PATH}"
    $SUDO chmod 755 "${OMNI_BIN_PATH}"
}

# --- write systemd service file ---
create_systemd_service_file() {
    info "Creating systemd service file ${FILE_OMNI_SERVICE}"
    {

        echo "[Unit]"
        echo "Description=AccuKnox Omni"
        echo "After=network-online.target"
        echo "Wants=network-online.target"
        echo
        echo "[Install]"
        echo "WantedBy=multi-user.target"
        echo
        echo "[Service]"
        echo "Type=simple"
        echo "TimeoutStartSec=infinity"
        echo "User=root"
        echo "CPUQuota=$OMNI_CPU_QUOTA"
        echo "MemoryMax=$OMNI_MAX_MEMORY"
        echo "StandardOutput=journal"
        echo "StandardError=journal"
        echo "SyslogIdentifier=accuknox-omni"
        if [[ "${OMNI_SKIP_DB_DOWNLOAD}" != true && "${OMNI_SKIP_DB_DOWNLOAD}" != 1 ]]; then
            echo "ExecStartPre=${OMNI_BIN_PATH} ${DB_DOWNLOAD_CMD_EXEC}"
            if [[ $OMNI_SKIP_MALWARE_SCAN == false || $OMNI_SKIP_MALWARE_SCAN == 0 ]]; then
                if [[ -x "$(command -v freshclam)" ]]; then
                    echo "ExecStartPre=freshclam"
                fi
            fi
        fi
        echo "ExecStart=${OMNI_BIN_PATH} ${AGENT_CMD_EXEC}"
    } | $SUDO tee "${FILE_OMNI_SERVICE}" >/dev/null
}

# --- write systemd timer file ---
create_systemd_timer_file() {
    info "Creating systemd timer file ${FILE_OMNI_TIMER}"
    {
        echo "[Unit]"
        echo "Description=Run AccuKnox Omni periodically"
        echo "After=omni.service"
        echo
        echo "[Timer]"
        echo "OnCalendar=daily"
        echo "Persistent=true"
        echo "AccuracySec=1h"
        echo "RandomizedDelaySec=10m"
        echo
        echo "[Install]"
        echo "WantedBy=timers.target"
    } | $SUDO tee "${FILE_OMNI_TIMER}" >/dev/null
}

create_uninstall_script() {
    info "Creating uninstall script ${FILE_UNINSTALL_SCRIPT}"
    {
        echo "#!/usr/bin/env bash"
        echo
        echo "set -euo pipefail"
        echo
        echo "$SUDO systemctl disable omni.timer omni.service --now 2>/dev/null || true"
        echo "$SUDO rm -rf $FILE_OMNI_SERVICE $FILE_OMNI_TIMER $OMNI_BIN_PATH $OMNI_HOME_DIR $FILE_UNINSTALL_SCRIPT"
    } | $SUDO tee "${FILE_UNINSTALL_SCRIPT}" >/dev/null
    $SUDO chmod 755 "${FILE_UNINSTALL_SCRIPT}"
}

{
    setup_env "--artifact-token-file=$(filepath_join "$OMNI_HOME_DIR" artifact.tok)" "--vuln-db-directory=$OMNI_HOME_DIR" "$@"
    verify_systemd
    verify_omni_url
    setup_token
    setup_tmp
    info "Stopping existing timer & service, if present"
    $SUDO systemctl disable omni.timer omni.service --now 2>/dev/null || true
    if [[ "${OMNI_SKIP_DOWNLOAD}" != true && "${OMNI_SKIP_DOWNLOAD}" != 1 ]]; then
        download_binary
    fi
    verify_omni_is_executable
    create_uninstall_script
    create_systemd_service_file
    create_systemd_timer_file
    info "Enabling timer & service"
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable omni.service
    $SUDO systemctl enable omni.timer --now
    if [[ "${OMNI_TRIGGER_IMMEDIATELY}" != false && "${OMNI_SKIP_DOWNLOAD}" != 0 ]]; then
        info "Starting scan..."
        $SUDO systemctl restart omni.service
    fi
}

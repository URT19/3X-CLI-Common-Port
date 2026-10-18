#!/usr/bin/env bash
#
# WS Port Remapper
#
# Puts many 3x-ui (Sanaei) inbounds behind ONE shared public port.
#
#   * WebSocket inbounds  -> TLS is terminated by nginx, requests are routed by SNI + path.
#   * WS + Reality inbounds -> passed through untouched by nginx (stream + ssl_preread),
#                            routed by the Reality serverNames.
#
# Every inbound is moved to 127.0.0.1:<local port>, a "host" entry is written to the panel
# so subscription links carry the public address/port/TLS fields automatically, and
# nginx (and haproxy, when present) is checked for port conflicts and rebuilt.
#
# Requires: Ubuntu/Debian, root, 3x-ui (Sanaei) with the Hosts API, nginx, jq, sqlite3, curl.
# License : MIT
#
# shellcheck disable=SC2034  # *_CERT and *_KEY are read indirectly through grp_get
set -uo pipefail

readonly SCRIPT_NAME="WS Port Remapper"
readonly SCRIPT_VERSION="2.0.0"

CONF_DIR="/etc/ws-port-remapper"
CONF_FILE="${CONF_DIR}/settings.env"
BACKUP_ROOT="${CONF_DIR}/backups"
STATE_FILE="${CONF_DIR}/state.json"   # inbound id -> group, kept after TLS is stripped
ORIGIN_DIR="${CONF_DIR}/origin"       # original streamSettings, saved before TLS is stripped
LOG_FILE="/var/log/ws-port-remapper.log"
RUN_ID="$(date +%Y%m%d-%H%M%S)"

NGINX_MANAGED="/etc/nginx/sites-available/ws-port-remapper.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/ws-port-remapper.conf"
# Main-context include dir of the stock Debian/Ubuntu nginx.conf; the stream block lives here.
STREAM_CONF="/etc/nginx/modules-enabled/90-ws-port-remapper-stream.conf"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"

# 3x-ui API routes (see the Hosts API reference of the panel).
API_LIST="/panel/api/inbounds/list"
API_GET="/panel/api/inbounds/get"          # + /<inboundId>
API_UPDATE="/panel/api/inbounds/update"    # + /<inboundId>
API_HOST_ADD="/panel/api/hosts/add"
API_HOST_UPDATE="/panel/api/hosts/update"          # + /<groupId>
API_HOST_BY_INBOUND="/panel/api/hosts/byInbound"   # + /<inboundId>

CIPHER_SUITES="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
# Two TCP fragment masks applied to CDN hosts in "default" host-security mode.
FINALMASK='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","1","104"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["1","114"],"delays":["1"],"maxSplit":"11"}}]}'

# ---------------------------------------------------------------------------
# Settings (defaults < settings file < environment/flags)
# ---------------------------------------------------------------------------
PANEL_URL=""
API_TOKEN=""
DB_PATH="/etc/x-ui/x-ui.db"
INTERNAL_BASE_PORT="10010"   # first local port handed to moved inbounds
INTERNAL_TLS_BASE="11443"    # first loopback TLS port, only used when Reality shares a port
PUBLIC_PORT="8443"           # shared public port for every group (see --port)

CDN_ADDRESS=""
CDN_SNI=""
CDN_CERT=""
CDN_KEY=""
CDN_REMARK="ws cdn tls"

DIRECT_ADDRESS=""            # empty = use the direct SNI domain
DIRECT_SNI=""
DIRECT_CERT=""
DIRECT_KEY=""
DIRECT_PORT=""               # empty = use PUBLIC_PORT (nginx separates the groups by SNI)
DIRECT_REMARK="ws direct tls"

REALITY_ADDRESS=""           # empty = direct address, then direct SNI
REALITY_PORT=""              # empty = use PUBLIC_PORT
REALITY_REMARK="reality direct"

FINGERPRINT="chrome"
ALPN="http/1.1"
ECH_CONFIG="cloudflare-ech.com+udp://1.1.1.1"
SERVICES="x-ui nginx"
HOST_SECURITY_MODE="default" # default = this script's values, clone = copy from the original inbound

SETTINGS_VARS=(PANEL_URL API_TOKEN DB_PATH INTERNAL_BASE_PORT INTERNAL_TLS_BASE PUBLIC_PORT
  CDN_ADDRESS CDN_SNI CDN_CERT CDN_KEY CDN_REMARK
  DIRECT_ADDRESS DIRECT_SNI DIRECT_CERT DIRECT_KEY DIRECT_PORT DIRECT_REMARK
  REALITY_ADDRESS REALITY_PORT REALITY_REMARK
  FINGERPRINT ALPN ECH_CONFIG SERVICES HOST_SECURITY_MODE)

# Per-run options (not saved)
FILTER_REMARK=""
SEED_CDN_IDS=""
SEED_DIRECT_IDS=""
ONLY_IDS=""
EXCLUDE_IDS=""
TOKEN_FILE=""
TOKEN_FROM_FLAG=0
SAVE_TOKEN=1
INCLUDE_REALITY=1
SELECT_MODE=0
NGINX_ONLY=0
DEBUG=0
DRY_RUN=0
SHOW_ONLY=0

# Runtime state
CAND=()              # id|remark|port|path|group|kind|names           (before ports are assigned)
PLAN=()              # id|remark|old port|new port|path|group|kind|names
PRESENT_GROUPS=()
PUB_PORTS=""         # public ports in use, space separated
STREAM_PORTS=""      # public ports that need an nginx stream front (Reality present)
USED_PORTS=""
declare -A LOCAL_TLS=()   # public port -> loopback TLS port behind the stream front
HOST_RESP=""

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RST=$'\e[0m'; C_BOLD=$'\e[1m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'
  C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_MAG=$'\e[35m'; C_CYN=$'\e[36m'
else
  C_RST=""; C_BOLD=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_CYN=""
fi

# Hides the API token and the panel URL (its web base path is a secret) in anything printed or logged.
redact() {
  local s="$1"
  [[ -n "$API_TOKEN" ]] && s="${s//"$API_TOKEN"/<token>}"
  [[ -n "$PANEL_URL" ]] && s="${s//"${PANEL_URL%/}"/<panel>}"
  printf '%s' "$s"
}

log() {
  local level="$1" color="$2"; shift 2
  local ts msg; ts="$(date '+%H:%M:%S')"; msg="$(redact "$*")"
  printf '%s[%s]%s %s%-5s%s %s\n' "$C_CYN" "$ts" "$C_RST" "$color" "$level" "$C_RST" "$msg"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
  printf '[%s] %-5s %s\n' "$ts" "$level" "$msg" >>"$LOG_FILE" 2>/dev/null || true
}
info()   { log INFO  "$C_CYN" "$*"; }
ok()     { log OK    "$C_GRN" "$*"; }
warn()   { log WARN  "$C_YEL" "$*"; }
err()    { log ERR   "$C_RED" "$*"; }
debug()  { if (( DEBUG )); then log DEBUG "$C_MAG" "$*" >&2; fi; return 0; }   # stderr: never mixes into $(...)
detail() { if (( DEBUG )); then printf '%s    %s%s\n' "$C_MAG" "$(redact "$*")" "$C_RST"; fi; return 0; }
die()    { err "$*"; exit 1; }

step() { printf '\n%s%s==== STEP %s: %s ====%s\n' "$C_BOLD" "$C_BLU" "$1" "$2" "$C_RST"; }

# In --debug mode every step stops and asks first.
confirm() {
  (( DEBUG )) || return 0
  local answer=""
  printf '%s?%s %s [y/N] ' "$C_YEL" "$C_RST" "$1"
  read -r answer </dev/tty || answer=""
  [[ "$answer" =~ ^[Yy]$ ]] || die "Stopped by user before: $1"
}

# ---------------------------------------------------------------------------
# Usage, settings, arguments
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

Usage: $0 [options]

Panel
  --panel-url URL         Panel base URL including the web base path
                          e.g. https://127.0.0.1:2053/your-secret-path
  --api-token TOKEN       3x-ui API token (visible in 'ps'; prefer the options below)
  --api-token-file PATH   Read the token from a file
                          Environment variable WSPR_API_TOKEN is also honoured
  --no-save-token         Do not store the token in the settings file
  --db PATH               x-ui database (default: ${DB_PATH})
  --internal-base PORT    First local port given to inbounds (default: ${INTERNAL_BASE_PORT})
  --internal-tls-base P   First loopback TLS port used behind the stream front (default: ${INTERNAL_TLS_BASE})

Public port
  --port PORT             The one public port every group is put behind (default: ${PUBLIC_PORT}).
                          CDN, direct and Reality all use it unless overridden below; nginx
                          tells them apart by SNI. With Cloudflare use 443, 2053, 2083, 2087, 2096 or 8443.

CDN group (WS inbounds whose SNI equals --cdn-sni)
  --cdn-address IP        Cloudflare edge IP written into the host entry
  --cdn-sni HOST          SNI / origin domain
  --cdn-cert PATH         fullchain.pem for that domain
  --cdn-key PATH          privkey.pem for that domain
  --cdn-remark TEXT       Host remark prefix (default: ${CDN_REMARK})

Direct group (WS inbounds whose SNI equals --direct-sni, or that have no SNI at all)
  --direct-address ADDR   Address in the host entry (default: the direct SNI)
  --direct-sni HOST       SNI / direct domain
  --direct-cert PATH      fullchain.pem
  --direct-key PATH       privkey.pem
  --direct-port PORT      Override --port for this group only
  --direct-remark TEXT    Host remark prefix (default: ${DIRECT_REMARK})

Reality group (WebSocket inbounds whose security is "reality"; other networks are ignored)
  --reality-address ADDR  Address in the host entry (default: direct address, then direct SNI)
  --reality-port PORT     Override --port for this group only
  --reality-remark TEXT   Host remark prefix (default: ${REALITY_REMARK})
  --no-reality            Ignore Reality inbounds

Host TLS fields
  --fingerprint FP        Fingerprint (default: ${FINGERPRINT})
  --host-security MODE    Where the host's TLS/Reality fields come from:
                            default  this script's values
                            clone    copied from the original inbound's own settings

Choosing inbounds
  --select                Interactive menu: pick which detected inbounds to process
  --only 22,26            Process only these inbound ids
  --exclude 3,7           Skip these inbound ids
  --filter-remark TEXT    Only process inbounds whose remark contains TEXT
  --cdn-ids 22,26         Tell the script these ids belong to the CDN group
  --direct-ids 3,19       Same for the direct group. Only needed for inbounds whose TLS/SNI was
                          already stripped by an earlier run; the choice is remembered.

Modes
  --nginx-only            Skip the panel. Rebuild nginx from the inbounds already moved to
                          127.0.0.1, fix port conflicts, tidy nginx and haproxy, reload.
  --services "A B"        Services to restart (default: ${SERVICES})
  --debug                 Show details and ask for confirmation at each step
  --dry-run               Plan only, change nothing
  --show-settings         Print stored settings and exit
  --version               Print the version
  -h, --help              Show this help

Values given here are saved to ${CONF_FILE} and reused on the next run.
EOF
}

load_settings() {
  if [[ -f "$CONF_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
    # settings saved by a pre-release build called the shared port CDN_PORT
    [[ -n "${CDN_PORT:-}" ]] && PUBLIC_PORT="$CDN_PORT"
    info "Loaded settings from ${CONF_FILE}"
  fi
  return 0
}

save_settings() {
  mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
  local v val
  {
    for v in "${SETTINGS_VARS[@]}"; do
      val="${!v}"
      [[ "$v" == "API_TOKEN" ]] && (( ! SAVE_TOKEN )) && val=""
      printf '%s=%q\n' "$v" "$val"
    done
  } >"$CONF_FILE"
  chmod 600 "$CONF_FILE"
  ok "Settings written to ${CONF_FILE}"
}

show_settings() {
  local v val
  for v in "${SETTINGS_VARS[@]}"; do
    val="${!v}"
    [[ "$v" == "API_TOKEN" && -n "$val" ]] && val="********"
    printf '%s%-20s%s %s\n' "$C_BOLD" "$v" "$C_RST" "$val"
  done
  printf 'Settings file: %s\n' "$CONF_FILE"
}

parse_args() {
  while (( $# )); do
    case "$1" in
      --debug|--dry-run|--show-settings|--select|--nginx-only|--no-reality|--no-save-token|--version|-h|--help) ;;
      *) (( $# >= 2 )) || die "Missing value for $1" ;;
    esac
    case "$1" in
      --panel-url)         PANEL_URL="$2"; shift 2 ;;
      --api-token)         API_TOKEN="$2"; TOKEN_FROM_FLAG=1; shift 2 ;;
      --api-token-file)    TOKEN_FILE="$2"; shift 2 ;;
      --no-save-token)     SAVE_TOKEN=0; shift ;;
      --db)                DB_PATH="$2"; shift 2 ;;
      --internal-base)     INTERNAL_BASE_PORT="$2"; shift 2 ;;
      --internal-tls-base) INTERNAL_TLS_BASE="$2"; shift 2 ;;
      --port)              PUBLIC_PORT="$2"; shift 2 ;;
      --cdn-address)       CDN_ADDRESS="$2"; shift 2 ;;
      --cdn-sni)           CDN_SNI="$2"; shift 2 ;;
      --cdn-cert)          CDN_CERT="$2"; shift 2 ;;
      --cdn-key)           CDN_KEY="$2"; shift 2 ;;
      --cdn-remark)        CDN_REMARK="$2"; shift 2 ;;
      --direct-address)    DIRECT_ADDRESS="$2"; shift 2 ;;
      --direct-sni)        DIRECT_SNI="$2"; shift 2 ;;
      --direct-cert)       DIRECT_CERT="$2"; shift 2 ;;
      --direct-key)        DIRECT_KEY="$2"; shift 2 ;;
      --direct-port)       DIRECT_PORT="$2"; shift 2 ;;
      --direct-remark)     DIRECT_REMARK="$2"; shift 2 ;;
      --reality-address)   REALITY_ADDRESS="$2"; shift 2 ;;
      --reality-port)      REALITY_PORT="$2"; shift 2 ;;
      --reality-remark)    REALITY_REMARK="$2"; shift 2 ;;
      --no-reality)        INCLUDE_REALITY=0; shift ;;
      --fingerprint)       FINGERPRINT="$2"; shift 2 ;;
      --host-security)     HOST_SECURITY_MODE="$2"; shift 2 ;;
      --only)              ONLY_IDS="$2"; shift 2 ;;
      --exclude)           EXCLUDE_IDS="$2"; shift 2 ;;
      --select)            SELECT_MODE=1; shift ;;
      --filter-remark)     FILTER_REMARK="$2"; shift 2 ;;
      --cdn-ids)           SEED_CDN_IDS="$2"; shift 2 ;;
      --direct-ids)        SEED_DIRECT_IDS="$2"; shift 2 ;;
      --nginx-only)        NGINX_ONLY=1; shift ;;
      --services)          SERVICES="$2"; shift 2 ;;
      --debug)             DEBUG=1; shift ;;
      --dry-run)           DRY_RUN=1; shift ;;
      --show-settings)     SHOW_ONLY=1; shift ;;
      --version)           printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      -h|--help)           usage; exit 0 ;;
      *)                   die "Unknown option: $1 (see --help)" ;;
    esac
  done
}

# Token precedence: --api-token, then --api-token-file, then $WSPR_API_TOKEN, then the settings file.
resolve_token() {
  if [[ -n "$TOKEN_FILE" ]]; then
    [[ -r "$TOKEN_FILE" ]] || die "Cannot read token file: ${TOKEN_FILE}"
    API_TOKEN="$(tr -d '[:space:]' <"$TOKEN_FILE")"
  elif (( ! TOKEN_FROM_FLAG )) && [[ -n "${WSPR_API_TOKEN:-}" ]]; then
    API_TOKEN="$WSPR_API_TOKEN"
  fi
}

# ---------------------------------------------------------------------------
# Groups: cdn, direct (WebSocket, TLS terminated by nginx) and reality (passed through)
# ---------------------------------------------------------------------------
grp_get() { # group, field (SNI|CERT|KEY|REMARK)
  local v="${1^^}_${2}"
  printf '%s' "${!v}"
}

grp_port() {
  case "$1" in
    cdn)     printf '%s' "$PUBLIC_PORT" ;;
    direct)  printf '%s' "${DIRECT_PORT:-$PUBLIC_PORT}" ;;
    reality) printf '%s' "${REALITY_PORT:-$PUBLIC_PORT}" ;;
  esac
}

grp_address() {
  case "$1" in
    cdn)     printf '%s' "$CDN_ADDRESS" ;;
    direct)  printf '%s' "${DIRECT_ADDRESS:-$DIRECT_SNI}" ;;
    reality) printf '%s' "${REALITY_ADDRESS:-${DIRECT_ADDRESS:-$DIRECT_SNI}}" ;;
  esac
}

state_get() { [[ -s "$STATE_FILE" ]] && jq -r --arg id "$1" '.[$id] // empty' "$STATE_FILE" 2>/dev/null; return 0; }

state_set() { # inbound id, group
  local tmp
  mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
  [[ -s "$STATE_FILE" ]] || echo '{}' >"$STATE_FILE"
  tmp=$(mktemp)
  jq --arg id "$1" --arg g "$2" '.[$id] = $g' "$STATE_FILE" >"$tmp" && install -m 600 "$tmp" "$STATE_FILE"
  rm -f "$tmp"
}

seed_state() {
  local i
  (( DRY_RUN )) && return 0
  for i in ${SEED_CDN_IDS//,/ };    do [[ "$i" =~ ^[0-9]+$ ]] && state_set "$i" cdn    && debug "Remembered inbound ${i} as cdn"; done
  for i in ${SEED_DIRECT_IDS//,/ }; do [[ "$i" =~ ^[0-9]+$ ]] && state_set "$i" direct && debug "Remembered inbound ${i} as direct"; done
  return 0
}

# Maps an inbound to a group name (empty = no match).
# Reality is always its own group. For WebSocket: SNI match, then the group remembered from an
# earlier run (the SNI is gone once TLS has been stripped), then "no SNI at all" = direct.
classify() { # sni, inbound id, kind
  local sni="${1,,}" saved
  if [[ "$3" == "reality" ]]; then
    (( INCLUDE_REALITY )) && echo reality
    return 0
  fi
  if   [[ -n "$CDN_SNI"    && "$sni" == "${CDN_SNI,,}" ]];    then echo cdn; return 0
  elif [[ -n "$DIRECT_SNI" && "$sni" == "${DIRECT_SNI,,}" ]]; then echo direct; return 0
  fi
  if [[ -z "$sni" ]]; then
    saved=$(state_get "$2")
    if [[ "$saved" == "cdn" || "$saved" == "direct" ]]; then echo "$saved"; return 0; fi
    [[ -n "$DIRECT_SNI" ]] && echo direct
  fi
  return 0
}

# Public ports to keep local ports away from, before the plan exists.
compute_pub_ports() {
  PUB_PORTS=""
  [[ -n "$CDN_SNI" ]]    && PUB_PORTS+="$(grp_port cdn) "
  [[ -n "$DIRECT_SNI" ]] && PUB_PORTS+="$(grp_port direct) "
  (( INCLUDE_REALITY ))  && PUB_PORTS+="$(grp_port reality) "
  PUB_PORTS=$(uniq_ports <<<"$PUB_PORTS")
}

# Reads port numbers (any whitespace) on stdin, prints them sorted and de-duplicated on one line.
uniq_ports() { tr -s '[:space:]' '\n' | sed '/^$/d' | sort -un | tr '\n' ' '; }

is_pub_port() { [[ " ${PUB_PORTS} " == *" $1 "* ]]; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
db_q() { sqlite3 -batch -separator '|' "$DB_PATH" "$1"; }

is_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

port_listening() { ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q .; }

port_busy_by_other() { # listening, and not nginx
  local out; out=$(ss -Hltnp "( sport = :$1 )" 2>/dev/null)
  [[ -n "$out" ]] && ! grep -q '"nginx"' <<<"$out"
}

port_in_db() { # port, inbound id to ignore
  local n
  n=$(db_q "SELECT COUNT(*) FROM inbounds WHERE port=$1 AND id<>${2:-0};")
  [[ "${n:-0}" -gt 0 ]]
}

# Prints config files that declare the given port (nginx files other than ours, haproxy).
config_conflicts() {
  local port="$1"
  if [[ -f "$HAPROXY_CFG" ]] && grep -Eq "^[[:space:]]*bind[[:space:]].*:${port}([[:space:]]|\$)" "$HAPROXY_CFG"; then
    echo "$HAPROXY_CFG"
  fi
  grep -rlE "^[[:space:]]*listen[[:space:]]+([^;]*[: ])?${port}[^0-9]" /etc/nginx 2>/dev/null \
    | grep -vxF -e "$NGINX_MANAGED" -e "$STREAM_CONF" || true
}

backup_file() {
  local dest="${BACKUP_ROOT}/${RUN_ID}"
  mkdir -p "$dest"
  cp -a "$1" "${dest}/$(tr / _ <<<"$1")"
  debug "Backed up $1 to ${dest}"
}

# Prints: id|remark|port|ws path|sni|security|listen|kind|names
#   kind  = ws | reality     names = comma separated Reality serverNames (dest host if none)
# Rows are read as raw JSON and parsed by jq, so inbounds with empty or invalid stream_settings
# (hysteria, tuic, amneziawg ...) are skipped instead of aborting the whole query.
detect_inbounds() {
  local raw
  raw=$(sqlite3 -batch -json "$DB_PATH" "SELECT id, remark, port, listen, stream_settings FROM inbounds ORDER BY id;") \
    || die "Cannot read inbounds from ${DB_PATH}"
  [[ -n "$raw" ]] || return 0
  jq -r --arg f "$FILTER_REMARK" '
    .[] | . as $r
    | ($r.stream_settings | try fromjson catch null) as $s
    | select(($s | type) == "object")
    | ($s.security // "none") as $sec
    | select($s.network == "ws")
    | select(($r.remark // "") | contains($f))
    | (if $sec == "reality" then
         ((($s.realitySettings.serverNames // []) | map(select(. != null and . != ""))) as $n
          | if ($n | length) > 0 then $n
            else [($s.realitySettings.dest // "" | tostring | sub(":[0-9]+$"; ""))] | map(select(. != "")) end)
       else [] end) as $names
    | ([$s.tlsSettings.serverName, $s.wsSettings.host, $s.wsSettings.headers.Host]
        | map(select(. != null and . != "")) | .[0] // "") as $sni
    | [$r.id, ($r.remark // ""), $r.port,
       (if $sec == "reality" then "" else ($s.wsSettings.path // "") end),
       (if $sec == "reality" then ($names[0] // "") else $sni end),
       $sec, ($r.listen // ""),
       (if $sec == "reality" then "reality" else "ws" end),
       ($names | join(","))]
    | join("|")
  ' <<<"$raw"
}

# ---------------------------------------------------------------------------
# Panel API
# ---------------------------------------------------------------------------
api() { # method path [json body]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sk --max-time 25 -X "$method" -H "Authorization: Bearer ${API_TOKEN}" -H "Accept: application/json")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data-binary "$body")
  debug "HTTP ${method} ${PANEL_URL%/}${path}"
  curl "${args[@]}" "${PANEL_URL%/}${path}"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
ensure_tools() {
  local t missing=()
  for t in sqlite3 jq curl ss nginx systemctl; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if (( ${#missing[@]} )); then
    warn "Missing tools: ${missing[*]}"
    detail "Packages to install: sqlite3 jq curl iproute2 nginx"
    confirm "Install missing packages"
    (( DRY_RUN )) && { info "dry-run: package install skipped"; return 0; }
    apt-get update -qq || warn "apt-get update reported errors, trying the install anyway"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 jq curl iproute2 nginx \
      || die "Package install failed"
    ok "Packages installed"
  else
    ok "Required tools present"
  fi
}

validate_base() {
  [[ -n "$PANEL_URL" ]] || die "Missing --panel-url"
  [[ -n "$API_TOKEN" ]] || die "Missing API token (--api-token-file, \$WSPR_API_TOKEN or --api-token)"
  [[ -f "$DB_PATH" ]]   || die "Database not found: ${DB_PATH}"
  validate_ports
  [[ "$HOST_SECURITY_MODE" == "default" || "$HOST_SECURITY_MODE" == "clone" ]] \
    || die "Invalid --host-security '${HOST_SECURITY_MODE}' (use default or clone)"
  ok "Base settings validated (host security: ${HOST_SECURITY_MODE})"
}

validate_ports() {
  is_port "$PUBLIC_PORT"        || die "Invalid public port: ${PUBLIC_PORT}"
  [[ -z "$DIRECT_PORT" ]]  || is_port "$DIRECT_PORT"  || die "Invalid direct port: ${DIRECT_PORT}"
  [[ -z "$REALITY_PORT" ]] || is_port "$REALITY_PORT" || die "Invalid reality port: ${REALITY_PORT}"
  is_port "$INTERNAL_BASE_PORT" || die "Invalid internal base port: ${INTERNAL_BASE_PORT}"
  is_port "$INTERNAL_TLS_BASE"  || die "Invalid internal TLS base port: ${INTERNAL_TLS_BASE}"
  [[ -n "${CDN_SNI}${DIRECT_SNI}" ]] || (( INCLUDE_REALITY )) || die "Set --cdn-sni and/or --direct-sni"
}

validate_groups() {
  local g sni cert key
  for g in "${PRESENT_GROUPS[@]}"; do
    if [[ "$g" == "reality" ]]; then
      [[ -n "$(grp_address reality)" ]] || die "Group reality: set --reality-address (or --direct-address / --direct-sni)"
      ok "Group reality: port=$(grp_port reality) address=$(grp_address reality) (passed through, no certificate needed)"
      continue
    fi
    sni=$(grp_get "$g" SNI); cert=$(grp_get "$g" CERT); key=$(grp_get "$g" KEY)
    [[ -n "$sni" ]]  || die "Group ${g}: missing SNI (--${g}-sni)"
    [[ -f "$cert" ]] || die "Group ${g}: certificate not found: ${cert:-<empty>} (--${g}-cert)"
    [[ -f "$key" ]]  || die "Group ${g}: private key not found: ${key:-<empty>} (--${g}-key)"
    if [[ "$g" == "cdn" && -z "$CDN_ADDRESS" ]]; then die "Group cdn: missing --cdn-address"; fi
    ok "Group ${g}: sni=${sni} port=$(grp_port "$g") address=$(grp_address "$g")"
  done
}

# ---------------------------------------------------------------------------
# Plan: detect, classify, choose, assign local ports
# ---------------------------------------------------------------------------
# A candidate local port must not be a public port, taken in this plan, busy, in the DB or in a config.
port_free_for() { # candidate, inbound id, current port
  local p="$1" id="$2" cur="$3"
  is_pub_port "$p" && return 1
  [[ " ${USED_PORTS} " == *" ${p} "* ]] && return 1
  [[ "$p" == "$cur" ]] && return 0
  port_listening "$p" && return 1
  port_in_db "$p" "$id" && return 1
  [[ -z "$(config_conflicts "$p")" ]] || return 1
  return 0
}

id_selected() { # --only / --exclude
  local id="$1"
  if [[ -n "$ONLY_IDS" && ",${ONLY_IDS// /}," != *",${id},"* ]]; then return 1; fi
  if [[ -n "$EXCLUDE_IDS" && ",${EXCLUDE_IDS// /}," == *",${id},"* ]]; then return 1; fi
  return 0
}

# Interactive menu over CAND. Input comes from the terminal (SELECT_INPUT overrides it, for tests).
select_interactive() {
  local i n=${#CAND[@]} id remark port path grp kind names answer tok a b
  local -A keep=()
  local -a picked=()
  (( n )) || return 0

  printf '\n%s%-4s %-6s %-30s %-8s %-8s %-7s %s%s\n' "$C_BOLD" "NO" "ID" "REMARK" "GROUP" "KIND" "PORT" "ROUTE" "$C_RST"
  for (( i = 0; i < n; i++ )); do
    IFS='|' read -r id remark port path grp kind names <<<"${CAND[i]}"
    printf '%-4s %-6s %-30s %-8s %-8s %-7s %s\n' "$((i + 1))" "$id" "$remark" "$grp" "$kind" "$port" "${path:-$names}"
  done
  printf '%s?%s Select inbounds (numbers like 1,3 or ranges 1-3, "all", "q" to quit) [all]: ' "$C_YEL" "$C_RST"
  read -r answer <"${SELECT_INPUT:-/dev/tty}" || answer=""
  answer="${answer:-all}"
  [[ "$answer" == "q" || "$answer" == "Q" ]] && die "Cancelled by user"
  [[ "$answer" == "all" ]] && return 0

  for tok in ${answer//,/ }; do
    if   [[ "$tok" =~ ^([0-9]+)-([0-9]+)$ ]]; then a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
    elif [[ "$tok" =~ ^[0-9]+$ ]];            then a="$tok"; b="$tok"
    else die "Invalid selection: '${tok}'"; fi
    (( a >= 1 && b <= n && a <= b )) || die "Selection out of range: '${tok}' (1-${n})"
    for (( i = a; i <= b; i++ )); do keep[$i]=1; done
  done
  for (( i = 1; i <= n; i++ )); do
    [[ -n "${keep[$i]:-}" ]] && picked+=("${CAND[i-1]}")
  done
  CAND=("${picked[@]}")
  (( ${#CAND[@]} )) || die "Nothing selected"
  ok "Selected ${#CAND[@]} of ${n} inbound(s)"
}

build_plan() {
  local id remark port path sni sec listen kind names grp row n dup next="$INTERNAL_BASE_PORT"
  local -A owner=()
  PLAN=(); CAND=(); USED_PORTS=""

  while IFS='|' read -r id remark port path sni sec listen kind names; do
    [[ -z "$id" ]] && continue

    if [[ "$kind" == "reality" ]]; then
      if (( ! INCLUDE_REALITY )); then debug "Reality inbound ${id} left out (--no-reality)"; continue; fi
      if [[ -z "$names" ]]; then warn "Inbound ${id} (${remark}): Reality has no serverNames or dest, skipped"; continue; fi
      grp="reality"
    else
      if [[ -z "$path" ]]; then warn "Inbound ${id} (${remark}) has no ws path, skipped"; continue; fi
      grp=$(classify "$sni" "$id" "$kind")
      if [[ -z "$grp" ]]; then warn "Inbound ${id} (${remark}): SNI '${sni:-none}' matches no configured group, skipped"; continue; fi
    fi

    if ! id_selected "$id"; then debug "Inbound ${id} (${remark}) left out by --only/--exclude"; continue; fi

    if (( NGINX_ONLY )); then
      # only inbounds that were already moved: loopback listener, TLS stripped (ws) or kept (reality)
      if [[ "$listen" != "127.0.0.1" ]] || { [[ "$kind" == "ws" && "$sec" != "none" ]]; }; then
        warn "Inbound ${id} (${remark}) is not moved behind nginx yet, skipped (run without --nginx-only first)"
        continue
      fi
    fi

    if [[ "$kind" == "reality" ]]; then
      # Reality is routed by SNI, so every serverName must be unique and must not be a WS domain
      dup=""
      for n in ${names//,/ }; do
        n="${n,,}"
        if [[ -n "${owner[$n]:-}" ]]; then dup="'${n}' (also used by inbound ${owner[$n]})"; break; fi
        if [[ "$n" == "${CDN_SNI,,}" || "$n" == "${DIRECT_SNI,,}" ]]; then dup="'${n}' (same as a CDN/direct domain)"; break; fi
      done
      if [[ -n "$dup" ]]; then
        warn "Inbound ${id} (${remark}): Reality SNI ${dup} cannot be routed, skipped"
        continue
      fi
      for n in ${names//,/ }; do owner[${n,,}]="$id"; done
    fi

    CAND+=("${id}|${remark}|${port}|${path}|${grp}|${kind}|${names}")
  done < <(detect_inbounds)

  (( SELECT_MODE )) && select_interactive

  for row in "${CAND[@]}"; do
    IFS='|' read -r id remark port path grp kind names <<<"$row"
    if (( NGINX_ONLY )); then
      PLAN+=("${id}|${remark}|${port}|${port}|${path}|${grp}|${kind}|${names}")   # upstream = the port it already uses
      continue
    fi
    while ! port_free_for "$next" "$id" "$port"; do next=$((next + 1)); done
    (( next < 65535 )) || die "Ran out of ports"
    PLAN+=("${id}|${remark}|${port}|${next}|${path}|${grp}|${kind}|${names}")
    USED_PORTS+=" ${next}"
    next=$((next + 1))
  done
}

compute_present_groups() {
  local row g seen=" "
  PRESENT_GROUPS=()
  for row in "${PLAN[@]}"; do
    g=$(cut -d'|' -f6 <<<"$row")
    if [[ "$seen" != *" ${g} "* ]]; then PRESENT_GROUPS+=("$g"); seen+="${g} "; fi
  done
  # from here on only the ports of the groups that are really present matter
  PUB_PORTS=$(for g in "${PRESENT_GROUPS[@]}"; do grp_port "$g"; echo; done | uniq_ports)
}

# Reality shares the public port through an nginx stream front. Any WebSocket group on the same
# port then listens on a loopback TLS port behind it (one per public port).
compute_stream() {
  local g p next="$INTERNAL_TLS_BASE"
  STREAM_PORTS=""; LOCAL_TLS=()
  for g in "${PRESENT_GROUPS[@]}"; do
    [[ "$g" == "reality" ]] && STREAM_PORTS+="$(grp_port reality) "
  done
  STREAM_PORTS=$(uniq_ports <<<"$STREAM_PORTS")
  for p in $STREAM_PORTS; do
    for g in "${PRESENT_GROUPS[@]}"; do
      [[ "$g" == "reality" || "$(grp_port "$g")" != "$p" ]] && continue
      while is_pub_port "$next" || [[ " ${USED_PORTS} " == *" ${next} "* ]] || port_busy_by_other "$next" || port_in_db "$next" 0; do
        next=$((next + 1))
      done
      LOCAL_TLS[$p]="$next"; USED_PORTS+=" ${next}"; next=$((next + 1))
      break
    done
  done
}

show_plan() {
  local row id remark old new path grp kind names
  printf '%s%-5s %-30s %-8s %-8s %-7s    %-7s %s%s\n' "$C_BOLD" "ID" "REMARK" "GROUP" "KIND" "OLD" "NEW" "ROUTE" "$C_RST"
  for row in "${PLAN[@]}"; do
    IFS='|' read -r id remark old new path grp kind names <<<"$row"
    printf '%-5s %-30s %-8s %-8s %-7s -> %-7s %s\n' "$id" "$remark" "$grp" "$kind" "$old" "$new" "${path:-sni: $names}"
  done
  local p
  for p in $STREAM_PORTS; do
    info "Port ${p}: nginx stream front (SNI routing) with Reality passthrough${LOCAL_TLS[$p]:+, WS TLS on 127.0.0.1:${LOCAL_TLS[$p]}}"
  done
}

# ---------------------------------------------------------------------------
# Checks, backups, conflicts
# ---------------------------------------------------------------------------
check_ports() {
  local row id _ ids="" p blocking owner files f
  for row in "${PLAN[@]}"; do
    IFS='|' read -r id _ <<<"$row"
    ids+="${id},"
  done
  ids="${ids%,}"

  for p in $PUB_PORTS; do
    blocking=$(db_q "SELECT id || ' ' || remark FROM inbounds WHERE port=${p} AND id NOT IN (${ids:-0});")
    [[ -n "$blocking" ]] && die "Public port ${p} is used by inbound(s) outside the plan: ${blocking}"
    ok "No inbound outside the plan uses public port ${p}"

    if port_listening "$p"; then
      owner=$(ss -Hltnp "( sport = :${p} )" | grep -o 'users:.*' || true)
      if grep -q '"nginx"' <<<"$owner"; then
        ok "Public port ${p} is held by nginx (will be rewritten)"
      else
        warn "Public port ${p} is held by: ${owner}"
      fi
    else
      ok "Public port ${p} is free"
    fi

    files=$(config_conflicts "$p")
    if [[ -n "$files" ]]; then
      warn "Config files declaring port ${p}:"
      while IFS= read -r f; do printf '    %s\n' "$f"; done <<<"$files"
    else
      ok "No nginx/haproxy config declares port ${p}"
    fi
  done
}

panel_check() {
  local resp
  resp=$(api GET "$API_LIST") || die "Cannot reach the panel (check --panel-url)"
  if ! jq -e '.success == true' <<<"$resp" >/dev/null 2>&1; then
    die "Panel rejected the API request. Response: $(head -c 300 <<<"$resp")"
  fi
  ok "Panel API reachable and token accepted"
  detail "Response (first 300 chars): $(head -c 300 <<<"$resp")"
}

backup_all() {
  backup_file "$DB_PATH"
  [[ -f "$NGINX_MANAGED" ]] && backup_file "$NGINX_MANAGED"
  [[ -f "$STREAM_CONF" ]] && backup_file "$STREAM_CONF"
  [[ -f "$HAPROXY_CFG" ]] && backup_file "$HAPROXY_CFG"
  ok "Backups stored in ${BACKUP_ROOT}/${RUN_ID}"
}

resolve_config_conflicts() {
  local p files f link
  for p in $PUB_PORTS; do
    files=$(config_conflicts "$p")
    if [[ -z "$files" ]]; then
      ok "No config conflicts on port ${p}"
      continue
    fi
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      warn "Resolving conflict on ${p} in ${f}"
      confirm "Resolve conflict on port ${p} in ${f}"
      if (( DRY_RUN )); then info "dry-run: would resolve ${f}"; continue; fi
      backup_file "$f"
      if [[ "$f" == /etc/nginx/* ]]; then
        for link in /etc/nginx/sites-enabled/*; do
          [[ -L "$link" && "$(readlink -f "$link")" == "$(readlink -f "$f")" ]] && rm -f "$link"
        done
        rm -f "$f"
        ok "Removed nginx file ${f} (backup kept)"
      else
        sed -i -E "/^[[:space:]]*bind[[:space:]].*:${p}([[:space:]]|\$)/ s/^/# ws-port-remapper: /" "$f"
        if command -v haproxy >/dev/null 2>&1 && ! haproxy -c -f "$f" >/dev/null 2>&1; then
          cp -a "${BACKUP_ROOT}/${RUN_ID}/$(tr / _ <<<"$f")" "$f"
          die "haproxy config invalid after change, restored ${f}"
        fi
        ok "Commented out port ${p} bind in ${f}"
      fi
    done <<<"$files"
  done
}

# ---------------------------------------------------------------------------
# Inbounds
# ---------------------------------------------------------------------------
# Saves the inbound's original streamSettings the first time TLS is stripped from it.
snapshot_origin() { # id, inbound object json
  local f="${ORIGIN_DIR}/${1}.json" s
  [[ -s "$f" ]] && return 0
  s=$(jq -c '(.streamSettings | if type == "string" then (try fromjson catch null) else . end) as $s
             | $s | select(type == "object" and (has("tlsSettings") or has("realitySettings")))' <<<"$2" 2>/dev/null)
  [[ -n "$s" ]] || return 0
  mkdir -p "$ORIGIN_DIR" && chmod 700 "$ORIGIN_DIR"
  printf '%s\n' "$s" >"$f" && chmod 600 "$f"
  debug "Saved original TLS settings of inbound ${1}"
}

# The inbound's original streamSettings: the saved copy if there is one, otherwise the live ones.
origin_stream() { # id
  local f="${ORIGIN_DIR}/${1}.json" get
  if [[ -s "$f" ]]; then cat "$f"; return 0; fi
  get=$(api GET "${API_GET}/${1}") || return 0
  jq -c '.obj.streamSettings | if type == "string" then (try fromjson catch {}) else (. // {}) end' <<<"$get" 2>/dev/null
  return 0
}

# Moves an inbound to 127.0.0.1:<port>.
#   ws       TLS is stripped (security none); nginx terminates it.
#   reality  stream settings are left alone; the Reality handshake still happens in xray.
apply_inbound() { # id, remark, new port, kind
  local id="$1" remark="$2" new_port="$3" kind="$4" get obj updated resp
  get=$(api GET "${API_GET}/${id}") || return 1
  obj=$(jq -c '.obj // empty' <<<"$get" 2>/dev/null) || return 1
  [[ -n "$obj" ]] || { err "Inbound ${id} not returned by the panel"; return 1; }

  if [[ "$kind" == "reality" ]]; then
    updated=$(jq -c --argjson port "$new_port" '.port = $port | .listen = "127.0.0.1"' <<<"$obj") || return 1
    detail "Inbound ${id} (${remark}): port -> ${new_port}, listen -> 127.0.0.1, Reality settings kept"
  else
    updated=$(jq -c --argjson port "$new_port" '
      def fix_stream:
        if type == "string"
        then (fromjson | .security = "none" | del(.tlsSettings) | tojson)
        else (.security = "none" | del(.tlsSettings))
        end;
      .port = $port | .listen = "127.0.0.1" | .streamSettings |= fix_stream
    ' <<<"$obj") || return 1
    detail "Inbound ${id} (${remark}): port -> ${new_port}, listen -> 127.0.0.1, security -> none"
  fi
  if (( DEBUG )); then detail "Payload (truncated): $(jq -c '{id, remark, port, listen}' <<<"$updated" | head -c 300)"; fi
  if (( DRY_RUN )); then info "dry-run: inbound ${id} not changed"; return 0; fi

  snapshot_origin "$id" "$obj"   # keep the original TLS/Reality data for the host entry
  resp=$(api POST "${API_UPDATE}/${id}" "$updated") || return 1
  if ! jq -e '.success == true' <<<"$resp" >/dev/null 2>&1; then
    err "Update failed for inbound ${id}: $(head -c 300 <<<"$resp")"
    return 1
  fi
  ok "Inbound ${id} (${remark}) now on 127.0.0.1:${new_port}"
}

# ---------------------------------------------------------------------------
# Host entries
# ---------------------------------------------------------------------------
# JSON object with the TLS/Reality-related host fields.
#   default: this script's values (fingerprint, ALPN, ciphers; ECH and mask for the cdn group)
#   clone:   copied from the original inbound's own settings; a field the inbound never had is
#            left out. Only the SNI falls back to a default because a host needs one.
host_security_fields() { # group, inbound id, kind, names
  local grp="$1" id="$2" kind="$3" names="$4" sni stream base extra='{}'
  if [[ "$kind" == "reality" ]]; then
    # The inbound's own Reality settings always go to its host (public key, short id, spiderX ...).
    sni="${names%%,*}"
    stream=$(origin_stream "$id"); [[ -n "$stream" ]] || stream='{}'
    jq -cn --argjson s "$stream" --arg sni "$sni" --arg fp "$FINGERPRINT" '
      ($s.realitySettings // {}) as $r | ($r.settings // {}) as $x
      | {sni: (if ($x.serverName // "") != "" then $x.serverName else $sni end),
         fingerprint: (if ($x.fingerprint // "") != "" then $x.fingerprint else $fp end)}
      + (if ($x.publicKey // "") != "" then {publicKey: $x.publicKey} else {} end)
      + (([($r.shortIds // [])[] | select(. != "")] | .[0]) as $sid
         | if $sid != null then {shortId: $sid} else {} end)
      + (if ($x.spiderX // "") != "" then {spiderX: $x.spiderX} else {} end)
      + (if ($x.mldsa65Verify // "") != "" then {mldsa65Verify: $x.mldsa65Verify} else {} end)'
    return 0
  fi

  sni="$(grp_get "$grp" SNI)"
  if [[ "$HOST_SECURITY_MODE" == "clone" ]]; then
    stream=$(origin_stream "$id"); [[ -n "$stream" ]] || stream='{}'
    jq -cn --argjson s "$stream" --arg sni "$sni" '
      ($s.tlsSettings // {}) as $t | ($t.settings // {}) as $x
      | {sni: (if ($t.serverName // "") != "" then $t.serverName else $sni end)}
      + (if (($t.alpn // []) | length) > 0 then {alpn: $t.alpn} else {} end)
      + (if ($x.fingerprint // "") != "" then {fingerprint: $x.fingerprint} else {} end)
      + (if ($t.cipherSuites // "") != "" then {cipherSuites: $t.cipherSuites} else {} end)
      + (if ($x.echConfigList // "") != "" then {echConfigList: $x.echConfigList} else {} end)
      + (if ($x.allowInsecure // null) != null then {allowInsecure: $x.allowInsecure} else {} end)
      + (if (($x.pinnedPeerCertSha256 // []) | length) > 0 then {pinnedPeerCertSha256: $x.pinnedPeerCertSha256} else {} end)
      + (if ($x.verifyPeerCertByName // "") != "" then {verifyPeerCertByName: $x.verifyPeerCertByName} else {} end)
      + (if (($s.finalmask // {}) | length) > 0 then {finalMask: $s.finalmask} else {} end)'
  else
    base=$(jq -cn --arg sni "$sni" --arg fp "$FINGERPRINT" --arg alpn "$ALPN" --arg ciphers "$CIPHER_SUITES" \
      '{sni: $sni, fingerprint: $fp, alpn: ($alpn | split(",")), cipherSuites: $ciphers}')
    # ECH and the fragment mask only make sense behind Cloudflare
    if [[ "$grp" == "cdn" ]]; then
      extra=$(jq -cn --arg ech "$ECH_CONFIG" --argjson mask "$FINALMASK" '{echConfigList: $ech, finalMask: $mask}')
    fi
    jq -cn --argjson b "$base" --argjson e "$extra" '$b + $e'
  fi
}

# Finds the stored host group with a given remark in a byInbound response.
host_find() { # json, remark
  jq -c --arg r "$2" '[.. | objects | select(has("groupId") and .remark == $r)] | .[0] // empty' <<<"$1" 2>/dev/null
}

# POSTs a host body. The panel validates field types one at a time and reports them as
# "cannot unmarshal X into Go struct field HostGroup.<field> of type <T>". On that error the
# offending field is converted to the type the panel wants and the request is retried.
post_host_adaptive() { # path, body -> HOST_RESP
  local path="$1" body="$2" resp="" msg field typ newbody tries=0
  while (( tries < 8 )); do
    resp=$(api POST "$path" "$body") || { HOST_RESP="$resp"; return 1; }
    if jq -e '.success == true' <<<"$resp" >/dev/null 2>&1; then HOST_RESP="$resp"; return 0; fi
    msg=$(jq -r '.obj.message // .msg // ""' <<<"$resp" 2>/dev/null)
    field=$(sed -nE 's/.*Go struct field [A-Za-z]+\.([A-Za-z0-9_]+) of type (.*)$/\1/p' <<<"$msg")
    typ=$(sed -nE 's/.*Go struct field [A-Za-z]+\.([A-Za-z0-9_]+) of type (.*)$/\2/p' <<<"$msg")
    [[ -n "$field" ]] || break
    debug "Panel wants '${field}' as ${typ}, converting and retrying"
    newbody=$(jq -c --arg f "$field" --arg t "$typ" '
      if .[$f] == null then .
      elif ($t | startswith("[]")) and ((.[$f] | type) == "string") then .[$f] = (if $f == "cipherSuites" then (.[$f] | split(":")) else [.[$f]] end)
      elif ($t == "string") and ((.[$f] | type) == "object" or (.[$f] | type) == "array") then .[$f] = (.[$f] | tojson)
      elif ($t | test("^(map|struct|json)")) and ((.[$f] | type) == "string") then .[$f] = (.[$f] | fromjson)
      else . end' <<<"$body" 2>/dev/null) || break
    [[ -n "$newbody" && "$newbody" != "$body" ]] || break
    body="$newbody"
    tries=$((tries + 1))
  done
  HOST_RESP="$resp"
  return 1
}

# Creates (or updates) the host entry of one inbound and reads it back to confirm the fields stuck.
#   ws       security "tls"   : the client does TLS with the shared port
#   reality  security "reality": the inbound's own Reality settings (SNI, fingerprint, public key,
#                               short id, spiderX) are copied into its host; falls back to "same"
create_host() { # id, remark, group, kind, names
  local id="$1" remark="$2" grp="$3" kind="$4" names="$5" body sec hremark addr port sni security
  local existing stored gid path bad=() key want got
  hremark="$(grp_get "$grp" REMARK) - ${remark}"
  addr="$(grp_address "$grp")"; port="$(grp_port "$grp")"
  security="tls"; [[ "$kind" == "reality" ]] && security="reality"

  sec=$(host_security_fields "$grp" "$id" "$kind" "$names")
  [[ -n "$sec" ]] || { err "Could not build host security fields for inbound ${id}"; return 1; }
  sni=$(jq -r '.sni' <<<"$sec")

  # Body follows the documented Hosts API (inboundIds + hosts[] + port + security).
  # overrideSniFromAddress=false keeps the SNI from being replaced by the CDN/server address.
  body=$(jq -cn \
    --arg remark "$hremark" --arg address "$addr" --argjson port "$port" --arg security "$security" \
    --argjson inbound "$id" --argjson sec "$sec" \
    '{inboundIds: [$inbound], remark: $remark, hosts: [$address], port: $port,
      security: $security, overrideSniFromAddress: false, keepSniBlank: false,
      tags: ["ws-port-remapper"], isDisabled: false} + $sec')

  detail "Host (${grp}/${kind}, ${HOST_SECURITY_MODE}) for inbound ${id}: ${addr}:${port}, security ${security}, sni ${sni}"
  detail "Fields: $(jq -c 'del(.cipherSuites)' <<<"$sec" | head -c 300)"
  if (( DRY_RUN )); then info "dry-run: host for inbound ${id} not created"; return 0; fi

  # Update the existing group with this remark instead of creating a duplicate.
  existing=$(api GET "${API_HOST_BY_INBOUND}/${id}") || existing=""
  stored=$(host_find "$existing" "$hremark")
  gid=$(jq -r '.groupId // empty' <<<"${stored:-null}" 2>/dev/null)
  if [[ -n "$gid" ]]; then
    path="${API_HOST_UPDATE}/${gid}"
    debug "Host group ${gid} already exists, updating it"
  else
    path="$API_HOST_ADD"
  fi

  if ! post_host_adaptive "$path" "$body" && [[ "$kind" == "reality" ]]; then
    # older panels may not know security "reality" on hosts: keep the inbound's own Reality keys
    warn "Panel refused a Reality host, retrying with security 'same'"
    security="same"
    sec=$(jq -c '{sni, fingerprint}' <<<"$sec")
    body=$(jq -c --arg s "$security" --argjson sec "$sec" '. + {security: $s} | del(.publicKey, .shortId, .spiderX, .mldsa65Verify) + $sec' <<<"$body")
    post_host_adaptive "$path" "$body" || true
  fi
  if ! jq -e '.success == true' <<<"$HOST_RESP" >/dev/null 2>&1; then
    err "Host request failed for inbound ${id}: $(head -c 400 <<<"$HOST_RESP")"
    return 1
  fi

  stored=$(host_find "$(api GET "${API_HOST_BY_INBOUND}/${id}")" "$hremark")
  if [[ -z "$stored" ]]; then
    warn "Host for inbound ${id} was accepted but not found by remark '${hremark}'; check the panel"
    return 0
  fi
  debug "Stored host: $(head -c 500 <<<"$stored")"

  # address, port and security must match; every TLS field that was sent must be stored too
  # (strings must contain what was sent, arrays/objects must be non-empty).
  got=$(jq -r '.address // "" | tostring' <<<"$stored");  [[ "$got" == *"$addr"* ]]     || bad+=("address (want '${addr}', got '${got}')")
  got=$(jq -r '.port // "" | tostring' <<<"$stored");     [[ "$got" == "$port" ]]       || bad+=("port (want '${port}', got '${got}')")
  got=$(jq -r '.security // "" | tostring' <<<"$stored"); [[ "$got" == "$security" ]]   || bad+=("security (want '${security}', got '${got}')")
  while IFS=$'\t' read -r key want; do
    [[ -n "$key" ]] || continue
    got=$(jq -r --arg k "$key" '.[$k] // "" | tostring' <<<"$stored")
    if [[ -n "$want" ]]; then
      [[ "$got" == *"$want"* ]] || bad+=("${key} (want '${want}', got '${got:0:60}')")
    else
      [[ -n "$got" && "$got" != "[]" && "$got" != "{}" && "$got" != "null" ]] || bad+=("${key} (empty, got '${got:0:60}')")
    fi
  done < <(jq -r 'to_entries[]
      | select(.key | IN("sni", "fingerprint", "alpn", "cipherSuites", "echConfigList", "finalMask", "verifyPeerCertByName", "pinnedPeerCertSha256", "publicKey", "shortId", "spiderX", "mldsa65Verify"))
      | [.key, (if (.value | type) == "string" then .value
                elif (.value | type) == "array" and ((.value | length) > 0) and ((.value[0] | type) == "string") then .value[0]
                else "" end)] | @tsv' <<<"$sec")
  if (( ${#bad[@]} )); then
    warn "Host created for inbound ${id} but these fields did not stick:"
    printf '      %s\n' "${bad[@]}"
    return 1
  fi
  ok "Host (${grp}) saved for inbound ${id}: ${addr}:${port} security=${security} sni=${sni}"
}

# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016  # $http_upgrade and $host are nginx variables, not shell ones
# HTTP side: one server block per WebSocket group. TLS is terminated here, location = ws path.
write_nginx_http() {
  local g p row id remark old new path rg kind names listen_line
  printf '%s\n' "# Managed by ${SCRIPT_NAME}. Regenerated on every run."
  for g in "${PRESENT_GROUPS[@]}"; do
    [[ "$g" == "reality" ]] && continue
    p="$(grp_port "$g")"
    if [[ -n "${LOCAL_TLS[$p]:-}" ]]; then listen_line="127.0.0.1:${LOCAL_TLS[$p]} ssl"; else listen_line="${p} ssl"; fi
    printf '\n# group: %s\n' "$g"
    printf 'server {\n'
    printf '    listen %s;\n' "$listen_line"
    printf '    server_name %s;\n' "$(grp_get "$g" SNI)"
    printf '    ssl_certificate %s;\n' "$(grp_get "$g" CERT)"
    printf '    ssl_certificate_key %s;\n' "$(grp_get "$g" KEY)"
    printf '    ssl_protocols TLSv1.2 TLSv1.3;\n'
    for row in "${PLAN[@]}"; do
      IFS='|' read -r id remark old new path rg kind names <<<"$row"
      [[ "$rg" == "$g" ]] || continue
      printf '\n    location %s {\n' "$path"
      printf '        proxy_pass http://127.0.0.1:%s;\n' "$new"
      printf '        proxy_http_version 1.1;\n'
      printf '        proxy_set_header Upgrade $http_upgrade;\n'
      printf '        proxy_set_header Connection "upgrade";\n'
      printf '        proxy_set_header Host $host;\n'
      printf '        proxy_read_timeout 3600s;\n'
      printf '        proxy_send_timeout 3600s;\n'
      printf '    }\n'
    done
    printf '\n    location / {\n        return 404;\n    }\n}\n'
  done
}

# shellcheck disable=SC2016  # $ssl_preread_server_name and $wspr_up_* are nginx variables
# Stream side: on every port shared with Reality, nginx reads the SNI of the ClientHello without
# terminating TLS. Reality serverNames go straight to their inbound; everything else goes to the
# loopback TLS listener of the WebSocket groups (or is dropped when there is none).
write_nginx_stream() {
  local p row id remark old new path grp kind names n
  printf '%s\n' "# Managed by ${SCRIPT_NAME}. Regenerated on every run."
  printf 'stream {\n'
  for p in $STREAM_PORTS; do
    printf '    map $ssl_preread_server_name $wspr_up_%s {\n' "$p"
    printf '        hostnames;\n'
    if [[ -n "${LOCAL_TLS[$p]:-}" ]]; then
      printf '        default 127.0.0.1:%s;\n' "${LOCAL_TLS[$p]}"
    else
      printf '        default 127.0.0.1:1;\n'
    fi
    for row in "${PLAN[@]}"; do
      IFS='|' read -r id remark old new path grp kind names <<<"$row"
      [[ "$kind" == "reality" && "$(grp_port reality)" == "$p" ]] || continue
      for n in ${names//,/ }; do printf '        %s 127.0.0.1:%s;\n' "${n,,}" "$new"; done
    done
    printf '    }\n\n'
    printf '    server {\n        listen %s;\n        ssl_preread on;\n        proxy_pass $wspr_up_%s;\n' "$p" "$p"
    printf '        proxy_connect_timeout 10s;\n        proxy_timeout 1h;\n    }\n'
  done
  printf '}\n'
}

nginx_has_stream() {
  compgen -G '/etc/nginx/modules-enabled/*stream*.conf' >/dev/null && return 0
  nginx -V 2>&1 | grep -Eq -- '--with-stream( |$)'
}

restore_or_remove() { # live file, saved copy ('' = there was none)
  if [[ -n "$2" ]]; then cp -a "$2" "$1"; else rm -f "$1"; fi
}

apply_nginx() {
  local g need_http=0 need_stream=0 tmp prev_http="" prev_stream="" test_out
  for g in "${PRESENT_GROUPS[@]}"; do
    if [[ "$g" == "reality" ]]; then need_stream=1; else need_http=1; fi
  done
  detail "nginx: http server blocks: ${need_http}, stream front: ${need_stream}"
  if (( DRY_RUN )); then info "dry-run: nginx config not written"; return 0; fi

  if (( need_stream )); then
    if ! nginx_has_stream; then
      warn "nginx has no stream module (needed for Reality passthrough)"
      confirm "Install libnginx-mod-stream"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libnginx-mod-stream >/dev/null 2>&1 \
        || die "Could not install libnginx-mod-stream"
    fi
    grep -q 'modules-enabled' /etc/nginx/nginx.conf 2>/dev/null \
      || die "/etc/nginx/nginx.conf does not include modules-enabled/*.conf; add that include (main context) first"
  fi

  [[ -f "$NGINX_MANAGED" ]] && { prev_http=$(mktemp); cp -a "$NGINX_MANAGED" "$prev_http"; }
  [[ -f "$STREAM_CONF" ]]   && { prev_stream=$(mktemp); cp -a "$STREAM_CONF" "$prev_stream"; }

  if (( need_http )); then
    tmp=$(mktemp); write_nginx_http >"$tmp"; install -m 644 "$tmp" "$NGINX_MANAGED"; rm -f "$tmp"
    ln -sfn "$NGINX_MANAGED" "$NGINX_ENABLED"
  else
    rm -f "$NGINX_MANAGED" "$NGINX_ENABLED"
  fi
  if (( need_stream )); then
    tmp=$(mktemp); write_nginx_stream >"$tmp"; install -m 644 "$tmp" "$STREAM_CONF"; rm -f "$tmp"
  else
    rm -f "$STREAM_CONF"
  fi

  if ! test_out=$(nginx -t 2>&1); then
    err "nginx test failed: ${test_out}"
    restore_or_remove "$NGINX_MANAGED" "$prev_http"
    restore_or_remove "$STREAM_CONF" "$prev_stream"
    if [[ -f "$NGINX_MANAGED" ]]; then ln -sfn "$NGINX_MANAGED" "$NGINX_ENABLED"; else rm -f "$NGINX_ENABLED"; fi
    die "Previous nginx config restored"
  fi
  rm -f "$prev_http" "$prev_stream"
  ok "nginx config written and tested (http: ${need_http}, stream: ${need_stream})"
}

# Removes dangling symlinks from sites-enabled and re-links the managed file.
tidy_nginx() {
  local link
  for link in /etc/nginx/sites-enabled/*; do
    [[ -L "$link" && ! -e "$link" ]] || continue
    warn "Dangling nginx symlink: ${link}"
    confirm "Remove ${link}"
    if (( DRY_RUN )); then info "dry-run: would remove ${link}"; continue; fi
    rm -f "$link" && ok "Removed ${link}"
  done
  if (( ! DRY_RUN )) && [[ -f "$NGINX_MANAGED" ]]; then ln -sfn "$NGINX_MANAGED" "$NGINX_ENABLED"; fi
  ok "nginx sites-enabled tidy"
}

# Strips trailing whitespace and repeated blank lines from haproxy.cfg, then validates it.
# The original is restored if the result does not pass haproxy -c.
tidy_haproxy() {
  local tmp
  if [[ ! -f "$HAPROXY_CFG" ]]; then info "No ${HAPROXY_CFG}, haproxy tidy skipped"; return 0; fi
  confirm "Tidy ${HAPROXY_CFG} (whitespace only, backup kept, validated afterwards)"
  if (( DRY_RUN )); then info "dry-run: haproxy config left as is"; return 0; fi
  backup_file "$HAPROXY_CFG"
  tmp=$(mktemp)
  sed -e 's/[[:space:]]*$//' "$HAPROXY_CFG" | cat -s >"$tmp"
  cat "$tmp" >"$HAPROXY_CFG"
  rm -f "$tmp"
  if command -v haproxy >/dev/null 2>&1; then
    if haproxy -c -f "$HAPROXY_CFG" >/dev/null 2>&1; then
      ok "haproxy config tidy and valid"
    else
      cp -a "${BACKUP_ROOT}/${RUN_ID}/$(tr / _ <<<"$HAPROXY_CFG")" "$HAPROXY_CFG"
      die "haproxy config failed validation, original restored"
    fi
  else
    warn "haproxy binary not found, config tidied but not validated"
  fi
}

# ---------------------------------------------------------------------------
# Services, verification, summary
# ---------------------------------------------------------------------------
restart_services() {
  local svc
  for svc in $SERVICES; do
    if ! systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q .; then
      warn "Service ${svc} not installed, skipped"
      continue
    fi
    confirm "Restart service ${svc}"
    if (( DRY_RUN )); then info "dry-run: ${svc} not restarted"; continue; fi
    systemctl restart "$svc" || warn "systemctl restart ${svc} returned an error"
    sleep 2
    if systemctl is-active --quiet "$svc"; then
      ok "${svc} is active"
    else
      err "${svc} is not active"
      systemctl status "$svc" --no-pager -n 15 | sed 's/^/    /'
      die "Service ${svc} failed to start"
    fi
  done
}

reload_service() { # unit name
  local svc="$1"
  if ! systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q .; then
    info "Service ${svc} not installed, skipped"
    return 0
  fi
  confirm "Reload service ${svc}"
  if (( DRY_RUN )); then info "dry-run: ${svc} not reloaded"; return 0; fi
  systemctl reload "$svc" 2>/dev/null || systemctl restart "$svc" || warn "Could not reload ${svc}"
  sleep 1
  if systemctl is-active --quiet "$svc"; then ok "${svc} is active"; else die "Service ${svc} is not active"; fi
}

verify() {
  local row id remark old new path grp kind names sni port code p
  for row in "${PLAN[@]}"; do
    IFS='|' read -r id remark old new path grp kind names <<<"$row"
    if port_listening "$new"; then
      ok "127.0.0.1:${new} listening (inbound ${id}, ${grp})"
    else
      warn "127.0.0.1:${new} not listening (inbound ${id}, ${grp})"
    fi
    [[ "$kind" == "ws" ]] || continue     # Reality cannot be probed without a client
    sni=$(grp_get "$grp" SNI); port=$(grp_port "$grp")
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${sni}:${port}:127.0.0.1" "https://${sni}:${port}${path}")
    case "$code" in
      400|426) ok "${sni}:${port}${path} routed to inbound ${id} (HTTP ${code})" ;;
      *)       warn "${sni}:${port}${path} returned HTTP ${code} (expected 400 or 426)" ;;
    esac
  done
  for p in $PUB_PORTS; do
    if port_listening "$p"; then ok "Public port ${p} listening"; else warn "Public port ${p} not listening"; fi
  done
}

summary() {
  local g row id remark old new path rg kind names
  printf '\n%s%s==== SUMMARY ====%s\n' "$C_BOLD" "$C_GRN" "$C_RST"
  for g in "${PRESENT_GROUPS[@]}"; do
    printf '%s[%s]%s %s:%s' "$C_BOLD" "$g" "$C_RST" "$(grp_address "$g")" "$(grp_port "$g")"
    if [[ "$g" == "reality" ]]; then printf '  security=reality (passthrough)\n'
    else printf '  sni=%s\n' "$(grp_get "$g" SNI)"; fi
    for row in "${PLAN[@]}"; do
      IFS='|' read -r id remark old new path rg kind names <<<"$row"
      [[ "$rg" == "$g" ]] || continue
      printf '  %-5s %-30s 127.0.0.1:%-6s %s\n' "$id" "$remark" "$new" "${path:-sni: $names}"
    done
  done
  printf 'Log     : %s\n' "$LOG_FILE"
  printf 'Backups : %s/%s\n' "$BACKUP_ROOT" "$RUN_ID"
}

# ---------------------------------------------------------------------------
# Main flows
# ---------------------------------------------------------------------------
nginx_only_main() {
  step 1 "Preflight (nginx only)"
  ensure_tools
  validate_ports
  [[ -f "$DB_PATH" ]] || die "Database not found: ${DB_PATH}"
  save_settings
  compute_pub_ports

  step 2 "Find inbounds already moved behind nginx"
  seed_state
  build_plan
  (( ${#PLAN[@]} )) || die "No moved inbound matched the configured domains (move them first by running without --nginx-only)"
  compute_present_groups
  validate_groups
  compute_stream
  show_plan
  confirm "Rebuild nginx for these inbounds"

  step 3 "Port conflict check"
  check_ports

  step 4 "Backups"
  backup_all

  step 5 "Resolve nginx/haproxy port conflicts"
  resolve_config_conflicts

  step 6 "Rebuild nginx config"
  apply_nginx

  step 7 "Tidy nginx and haproxy"
  tidy_nginx
  tidy_haproxy

  step 8 "Reload services"
  reload_service nginx
  [[ -f "$HAPROXY_CFG" ]] && reload_service haproxy

  step 9 "Verify"
  verify
  summary
}

main() {
  [[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }
  load_settings
  parse_args "$@"
  resolve_token

  if (( SHOW_ONLY )); then show_settings; exit 0; fi

  printf '%s%s%s v%s%s\n' "$C_BOLD" "$C_CYN" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$C_RST"
  (( DEBUG ))   && warn "Debug mode: each step asks for confirmation"
  (( DRY_RUN )) && warn "Dry run: no changes will be made"

  if (( NGINX_ONLY )); then nginx_only_main; exit 0; fi

  step 1 "Preflight"
  ensure_tools
  validate_base
  save_settings
  compute_pub_ports

  step 2 "Detect inbounds (WebSocket and Reality), classify, plan ports"
  seed_state
  build_plan
  (( ${#PLAN[@]} )) || die "No inbound matched (WS needs --cdn-sni/--direct-sni to match; filter: '${FILTER_REMARK:-none}')"
  compute_present_groups
  validate_groups
  compute_stream
  show_plan
  confirm "Apply this plan"

  step 3 "Port conflict check"
  check_ports
  confirm "Continue with port check results"

  step 4 "Panel API check"
  panel_check

  step 5 "Backups"
  backup_all

  step 6 "Resolve nginx/haproxy port conflicts"
  resolve_config_conflicts

  local row id remark old new path grp kind names
  step 7 "Move inbounds to local ports"
  for row in "${PLAN[@]}"; do
    IFS='|' read -r id remark old new path grp kind names <<<"$row"
    apply_inbound "$id" "$remark" "$new" "$kind" || die "Failed on inbound ${id}"
    (( DRY_RUN )) || [[ "$kind" == "reality" ]] || state_set "$id" "$grp"
  done

  step 8 "Write host entries"
  for row in "${PLAN[@]}"; do
    IFS='|' read -r id remark old new path grp kind names <<<"$row"
    create_host "$id" "$remark" "$grp" "$kind" "$names" || warn "Host step failed for inbound ${id}"
  done

  step 9 "Rebuild nginx public listeners"
  apply_nginx

  step 10 "Restart and check services"
  restart_services

  step 11 "Verify"
  verify
  summary
}

main "$@"

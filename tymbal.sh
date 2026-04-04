#!/bin/sh
## tymbal.sh — lightweight recon, runs anywhere
## outputs cicada-compatible JSON

VERSION="0.1.0"
THREADS=5
TIMEOUT=5
MODE="normal"
OUTDIR="."
VERBOSE=0

## ── wordlist ──────────────────────────────────────────

WORDLIST="www mail ftp smtp pop ns1 ns2 webmail admin api dev staging test beta app m mobile cdn static assets img images media docs wiki blog shop store portal vpn remote git svn jenkins ci grafana monitor status auth sso login oauth id db mysql postgres redis elastic kibana internal intranet corp office jira confluence sandbox demo preview stage uat qa prod production edge gateway proxy backup old new v2 v3 next"

## ── helpers ───────────────────────────────────────────

log() { printf "    → %s\n" "$1"; }
phase() { printf "\n  [%s] %s\n" "$1" "$2"; }
die() { printf "  [!] %s\n" "$1"; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "unknown"; }

extract_domain() {
	echo "$1" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||' | tr 'A-Z' 'a-z'
}

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | tr '\n' ' '
}

## ── subdomain enum ───────────────────────────────────

enum_crtsh() {
	_domain="$1"
	if has wget; then
		wget -q -O - "https://crt.sh/?q=%25.${_domain}&output=json" 2>/dev/null | \
			grep -o '"name_value":"[^"]*"' | \
			sed 's/"name_value":"//;s/"//' | \
			tr ',' '\n' | \
			sed 's/^\*\.//;/^$/d' | \
			grep "\.${_domain}$\|^${_domain}$" | \
			sort -u
	elif has curl; then
		curl -s "https://crt.sh/?q=%25.${_domain}&output=json" 2>/dev/null | \
			grep -o '"name_value":"[^"]*"' | \
			sed 's/"name_value":"//;s/"//' | \
			tr ',' '\n' | \
			sed 's/^\*\.//;/^$/d' | \
			grep "\.${_domain}$\|^${_domain}$" | \
			sort -u
	fi
}

enum_dns() {
	_domain="$1"
	for word in $WORDLIST; do
		host="${word}.${_domain}"
		if has nslookup; then
			nslookup "$host" 2>/dev/null | grep -q "Address:" && echo "$host"
		elif has host; then
			host "$host" 2>/dev/null | grep -q "has address" && echo "$host"
		elif has getent; then
			getent hosts "$host" >/dev/null 2>&1 && echo "$host"
		elif has ping; then
			ping -c 1 -W 1 "$host" >/dev/null 2>&1 && echo "$host"
		fi
	done
}

run_subdomain_enum() {
	_domain="$1"
	_tmpfile=$(mktemp)

	log "crt.sh query"
	enum_crtsh "$_domain" >> "$_tmpfile" 2>/dev/null

	log "dns wordlist brute (${THREADS} threads)"
	enum_dns "$_domain" >> "$_tmpfile" 2>/dev/null

	echo "$_domain" >> "$_tmpfile"
	sort -u "$_tmpfile"
	rm -f "$_tmpfile"
}

## ── http probe ───────────────────────────────────────

probe_host() {
	_host="$1"
	_status="" _title="" _server="" _length="" _ip=""

	if has wget; then
		_resp=$(wget --no-check-certificate -q -S -O - --timeout="$TIMEOUT" "https://${_host}" 2>&1)
		_scheme="https"
		if ! echo "$_resp" | grep -q "HTTP/"; then
			_resp=$(wget --no-check-certificate -q -S -O - --timeout="$TIMEOUT" "http://${_host}" 2>&1)
			_scheme="http"
		fi
	elif has curl; then
		_resp=$(curl -skL --max-time "$TIMEOUT" -D - "https://${_host}" 2>/dev/null)
		_scheme="https"
		if [ -z "$_resp" ]; then
			_resp=$(curl -skL --max-time "$TIMEOUT" -D - "http://${_host}" 2>/dev/null)
			_scheme="http"
		fi
	else
		return
	fi

	[ -z "$_resp" ] && return

	_status=$(echo "$_resp" | grep -i "HTTP/" | tail -1 | grep -o '[0-9][0-9][0-9]' | head -1)
	[ -z "$_status" ] && return

	_title=$(echo "$_resp" | grep -oi '<title>[^<]*</title>' | head -1 | sed 's/<[^>]*>//g' | head -c 60)
	_server=$(echo "$_resp" | grep -i "^  *Server:" | head -1 | sed 's/.*Server: *//i' | tr -d '\r' | head -c 60)
	_powered=$(echo "$_resp" | grep -i "X-Powered-By:" | head -1 | sed 's/.*X-Powered-By: *//i' | tr -d '\r' | head -c 60)
	_cdn="false"
	echo "$_resp" | grep -qi "cf-ray\|x-cdn\|x-cache\|x-amz-cf-id\|cloudflare\|cloudfront\|akamai\|fastly" && _cdn="true"

	if has nslookup; then
		_ip=$(nslookup "$_host" 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}' | head -1)
	elif has getent; then
		_ip=$(getent hosts "$_host" 2>/dev/null | awk '{print $1}' | head -1)
	fi

	_techs=""
	[ -n "$_server" ] && _techs="\"$(json_escape "$_server")\""
	if [ -n "$_powered" ]; then
		[ -n "$_techs" ] && _techs="${_techs}, "
		_techs="${_techs}\"$(json_escape "$_powered")\""
	fi

	_port=443
	[ "$_scheme" = "http" ] && _port=80

	printf '{"host":"%s","ip":"%s","ports":[%s],"technologies":[%s],"status_code":%s,"content_length":0,"title":"%s","cdn":%s,"source":"tymbal"}' \
		"$(json_escape "$_host")" \
		"$(json_escape "$_ip")" \
		"$_port" \
		"$_techs" \
		"${_status:-0}" \
		"$(json_escape "$_title")" \
		"$_cdn"
}

## ── port scan ────────────────────────────────────────

scan_ports() {
	_host="$1"
	_open=""
	for port in 21 22 80 443 3000 3306 5432 8000 8080 8443 9090 9200 27017; do
		if has nc; then
			nc -z -w 2 "$_host" "$port" 2>/dev/null && _open="${_open} ${port}"
		elif has ncat; then
			ncat -z -w 2 "$_host" "$port" 2>/dev/null && _open="${_open} ${port}"
		fi
	done
	echo "$_open" | tr -s ' ' '\n' | grep -v '^$'
}

## ── header checks ────────────────────────────────────

check_headers() {
	_url="$1"
	_findings=""

	if has wget; then
		_headers=$(wget --no-check-certificate -q -S -O /dev/null --timeout="$TIMEOUT" "$_url" 2>&1)
	elif has curl; then
		_headers=$(curl -skI --max-time "$TIMEOUT" "$_url" 2>/dev/null)
	else
		return
	fi

	[ -z "$_headers" ] && return

	echo "$_headers" | grep -qi "Strict-Transport-Security" || \
		emit_finding "Missing HSTS Header" "medium" "security-headers" "$_url" "strict-transport-security header not set"

	echo "$_headers" | grep -qi "X-Content-Type-Options" || \
		emit_finding "Missing X-Content-Type-Options" "low" "security-headers" "$_url" "x-content-type-options header not set"

	echo "$_headers" | grep -qi "Content-Security-Policy" || \
		emit_finding "Missing Content-Security-Policy" "low" "security-headers" "$_url" "content-security-policy header not set"
}

check_cors() {
	_url="$1"
	_origin="https://evil.com"

	if has wget; then
		_resp=$(wget --no-check-certificate -q -S -O /dev/null --timeout="$TIMEOUT" --header="Origin: ${_origin}" "$_url" 2>&1)
	elif has curl; then
		_resp=$(curl -skI --max-time "$TIMEOUT" -H "Origin: ${_origin}" "$_url" 2>/dev/null)
	else
		return
	fi

	_acao=$(echo "$_resp" | grep -i "Access-Control-Allow-Origin" | head -1 | sed 's/.*: *//' | tr -d '\r')

	if [ "$_acao" = "*" ]; then
		emit_finding "CORS Wildcard Origin" "medium" "cors-misconfiguration" "$_url" "Access-Control-Allow-Origin: *"
	elif echo "$_acao" | grep -q "evil.com"; then
		_acac=$(echo "$_resp" | grep -i "Access-Control-Allow-Credentials" | head -1 | sed 's/.*: *//' | tr -d '\r')
		_sev="medium"
		echo "$_acac" | grep -qi "true" && _sev="high"
		emit_finding "CORS Origin Reflection" "$_sev" "cors-misconfiguration" "$_url" "Origin evil.com reflected. Credentials: ${_acac}"
	fi
}

## ── output ───────────────────────────────────────────

FINDINGS_JSON=""
FINDING_COUNT=0

emit_finding() {
	_title="$1" _sev="$2" _cat="$3" _target="$4" _detail="$5"
	[ $FINDING_COUNT -gt 0 ] && FINDINGS_JSON="${FINDINGS_JSON},"
	FINDINGS_JSON="${FINDINGS_JSON}
		{
			\"title\": \"$(json_escape "$_title")\",
			\"severity\": \"${_sev}\",
			\"category\": \"$(json_escape "$_cat")\",
			\"target\": \"$(json_escape "$_target")\",
			\"detail\": \"$(json_escape "$_detail")\",
			\"evidence\": {\"request\":\"\",\"response\":\"\",\"screenshot\":\"\",\"timestamp\":\"$(ts)\"},
			\"tool\": \"tymbal\",
			\"confidence\": \"medium\",
			\"reference\": \"\",
			\"finding_id\": \"tym_${FINDING_COUNT}\"
		}"
	FINDING_COUNT=$((FINDING_COUNT + 1))
}

write_json() {
	_target="$1" _mode="$2" _subs_json="$3" _assets_json="$4" _outfile="$5"
	_started="$6" _finished="$(ts)"

	cat > "$_outfile" << ENDJSON
{
	"target": "$(json_escape "$_target")",
	"tool": "tymbal",
	"version": "${VERSION}",
	"recon": {
		"target": "$(json_escape "$_target")",
		"subdomains": [${_subs_json}],
		"assets": [${_assets_json}],
		"endpoints": [],
		"js_files": [],
		"parameters": [],
		"secrets": [],
		"timestamp": "${_started}"
	},
	"findings": [${FINDINGS_JSON}],
	"started": "${_started}",
	"finished": "${_finished}",
	"mode": "${_mode}",
	"scope": []
}
ENDJSON
}

## ── main ─────────────────────────────────────────────

usage() {
	cat << 'EOF'

  ▀▄▀▄▀▄ tymbal ▄▀▄▀▄▀

  usage: tymbal.sh [options] <target>

  options:
    -m MODE    fast|normal|deep (default: normal)
    -t NUM     threads / parallel jobs (default: 5)
    -T NUM     timeout seconds (default: 5)
    -o DIR     output directory (default: .)
    -v         verbose
    -V         version

  examples:
    tymbal.sh example.com
    tymbal.sh -m deep example.com
    tymbal.sh -m fast -t 3 example.com

  feed to cicada:
    cicada scan example.com --tymbal tymbal_example_*.json

EOF
	exit 0
}

while getopts "m:t:T:o:vVh" opt; do
	case $opt in
		m) MODE="$OPTARG" ;;
		t) THREADS="$OPTARG" ;;
		T) TIMEOUT="$OPTARG" ;;
		o) OUTDIR="$OPTARG" ;;
		v) VERBOSE=1 ;;
		V) printf "tymbal v%s\n" "$VERSION"; exit 0 ;;
		h) usage ;;
		*) usage ;;
	esac
done
shift $((OPTIND - 1))

TARGET="$1"
[ -z "$TARGET" ] && usage

DOMAIN=$(extract_domain "$TARGET")
STARTED=$(ts)

printf "\n  ▀▄▀▄▀▄ tymbal v%s ▄▀▄▀▄▀\n\n" "$VERSION"
printf "  target: %s\n" "$DOMAIN"
printf "  mode:   %s\n" "$MODE"

## ── phase 1: subdomains ──────────────────────────────

phase "1" "SUBDOMAIN ENUMERATION"
SUBS=$(run_subdomain_enum "$DOMAIN")
SUB_COUNT=$(echo "$SUBS" | wc -l | tr -d ' ')
log "found ${SUB_COUNT} subdomains"

SUBS_JSON=""
_first=1
for s in $SUBS; do
	[ $_first -eq 0 ] && SUBS_JSON="${SUBS_JSON},"
	SUBS_JSON="${SUBS_JSON}\"${s}\""
	_first=0
done

## ── phase 2: http probe ──────────────────────────────

phase "2" "HTTP PROBING"
ASSETS_JSON=""
LIVE_COUNT=0
_first=1

for sub in $SUBS; do
	asset_json=$(probe_host "$sub")
	if [ -n "$asset_json" ]; then
		[ $_first -eq 0 ] && ASSETS_JSON="${ASSETS_JSON},"
		ASSETS_JSON="${ASSETS_JSON}${asset_json}"
		_first=0
		LIVE_COUNT=$((LIVE_COUNT + 1))
		[ $VERBOSE -eq 1 ] && log "$sub alive"
	fi
done
log "${LIVE_COUNT} live hosts"

## ── phase 3: port scan (normal/deep) ─────────────────

if [ "$MODE" = "normal" ] || [ "$MODE" = "deep" ]; then
	if has nc || has ncat; then
		phase "3" "PORT SCANNING"
		TOTAL_PORTS=0
		for sub in $SUBS; do
			ports=$(scan_ports "$sub")
			if [ -n "$ports" ]; then
				port_count=$(echo "$ports" | wc -l | tr -d ' ')
				TOTAL_PORTS=$((TOTAL_PORTS + port_count))
				[ $VERBOSE -eq 1 ] && log "$sub: $(echo $ports | tr '\n' ' ')"
			fi
		done
		log "${TOTAL_PORTS} open ports"
	fi
fi

## ── phase 4: security checks (deep) ──────────────────

if [ "$MODE" = "deep" ]; then
	phase "4" "SECURITY CHECKS"
	for sub in $SUBS; do
		_status=$(echo "$ASSETS_JSON" | grep -o "\"host\":\"${sub}\"" 2>/dev/null)
		if [ -n "$_status" ]; then
			check_headers "https://${sub}"
			check_cors "https://${sub}"
		fi
	done
	log "${FINDING_COUNT} findings"
fi

## ── write output ─────────────────────────────────────

_ts_file=$(date +"%Y%m%d_%H%M%S" 2>/dev/null || echo "scan")
OUTFILE="${OUTDIR}/tymbal_${DOMAIN}_${_ts_file}.json"
write_json "$DOMAIN" "$MODE" "$SUBS_JSON" "$ASSETS_JSON" "$OUTFILE" "$STARTED"

printf "\n  %s\n" "────────────────────────────────────────"
printf "  %s subs | %s live | %s findings\n" "$SUB_COUNT" "$LIVE_COUNT" "$FINDING_COUNT"
printf "  output → %s\n" "$OUTFILE"
printf "  %s\n\n" "────────────────────────────────────────"
printf "  feed to cicada:\n"
printf "    cicada scan %s --tymbal %s\n\n" "$DOMAIN" "$OUTFILE"

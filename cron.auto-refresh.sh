#!/usr/bin/env bash
# Requires: bash, openssl, curl
#
# crontab 設定（每小時執行一次，log 依日期分檔，保留 30 天）：
#   0 * * * * /some/place/refresh.sh >> /var/log/sslmgr/refresh-$(date +\%Y-\%m-\%d).log 2>&1
#   30 0 * * * find /var/log/sslmgr -maxdepth 1 -name 'refresh-*.log' -mtime +30 -delete
#
# - 需先建立 log 資料夾：mkdir -p /var/log/sslmgr（重導向不會自動建立資料夾）
# - crontab 中的 % 需寫成 \%，否則會被 cron 當成換行；Synology 任務排程表則不需跳脫
# - 寫在 /etc/crontab 或 /etc/cron.d/ 時，時間欄位後需多加執行身分，例如 0 * * * * root /var/services/...
set -uo pipefail

CERT_DIR="."
CERT_FETCH_HOST=""
CERT_HOST_KEY=""
BUNDLE_CERT=1
UPDATE_BOUNDARY=$(( 7 * 86400 ))



log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$CERT_DIR" in
	/*) ;;
	*) CERT_DIR="$SCRIPT_DIR/$CERT_DIR" ;;
esac
CERT_FETCH_HOST="${CERT_FETCH_HOST%/}"

if [ -z "$CERT_FETCH_HOST" ]; then
	echo 'CERT_FETCH_HOST is not set!' >&2
	exit 1
fi

if [ -z "$CERT_HOST_KEY" ]; then
	echo 'CERT_HOST_KEY is not set!' >&2
	exit 1
fi

case "$BUNDLE_CERT" in
	0) FETCH_TYPE="crt"; FILE_MODE=644 ;;
	1) FETCH_TYPE="bundle"; FILE_MODE=600 ;;
	*)
		echo 'BUNDLE_CERT must be 0 or 1!' >&2
		exit 1
		;;
esac



KEY_PATH="$CERT_DIR/ssl.key"
CRT_PATH="$CERT_DIR/ssl.crt"

KEY_PUB="$(openssl pkey -in "$KEY_PATH" -pubout 2>/dev/null)"
if [ -z "$KEY_PUB" ]; then
	log "Error refreshing certificate: Unable to read private key: $KEY_PATH" >&2
	exit 1
fi

if command -v flock >/dev/null 2>&1; then
	exec 9>"$CERT_DIR/.auto-refresh.lock"
	flock -n 9 || exit 0
fi

LOCAL_END=""
if [ -f "$CRT_PATH" ]; then
	LOCAL_END="$(openssl x509 -in "$CRT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2)"
fi

if [ -n "$LOCAL_END" ] && openssl x509 -in "$CRT_PATH" -noout -checkend "$UPDATE_BOUNDARY" >/dev/null 2>&1; then
	log "$CERT_HOST_KEY: $LOCAL_END. Passed! ✅"
	exit 0
fi

log "$CERT_HOST_KEY: ${LOCAL_END:-no certificate}. Refreshing... ❌"



SIGNATURE="$(printf '{"key":"%s","ts":%d}' "$CERT_HOST_KEY" "$(( $(date +%s) / 10 ))" \
	| openssl dgst -sha256 -sign "$KEY_PATH" \
	| openssl base64 -A | tr '+/' '-_' | tr -d '=')"
if [ -z "$SIGNATURE" ]; then
	log "Error refreshing certificate: Unable to sign request!" >&2
	exit 1
fi

TMP_PATH="$(mktemp "$CERT_DIR/.ssl.crt.XXXXXX")" || exit 1
trap 'rm -f "$TMP_PATH"' EXIT

STATUS="$(curl -sS --max-time 30 -H "Authorization: $SIGNATURE" -o "$TMP_PATH" -w '%{http_code}' "$CERT_FETCH_HOST/ssl/$CERT_HOST_KEY/$FETCH_TYPE")"
case "$STATUS" in
	2??) ;;
	*)
		log "Error refreshing certificate: Unable to fetch $FETCH_TYPE! (status:$STATUS)" >&2
		exit 1
		;;
esac

REMOTE_END="$(openssl x509 -in "$TMP_PATH" -noout -enddate 2>/dev/null | cut -d= -f2)"
if [ -z "$REMOTE_END" ]; then
	log "Error refreshing certificate: Fetched certificate is invalid!" >&2
	exit 1
fi
if [ "$(openssl x509 -in "$TMP_PATH" -noout -pubkey)" != "$KEY_PUB" ]; then
	log "Error refreshing certificate: Fetched certificate does not match local private key!" >&2
	exit 1
fi
if [ "$FETCH_TYPE" = "bundle" ] && [ "$(openssl pkey -in "$TMP_PATH" -pubout 2>/dev/null)" != "$KEY_PUB" ]; then
	log "Error refreshing certificate: Fetched bundle does not contain local private key!" >&2
	exit 1
fi
if [ -n "$LOCAL_END" ] && cmp -s "$TMP_PATH" "$CRT_PATH"; then
	log "$CERT_HOST_KEY: remote certificate has not been renewed yet! ($REMOTE_END)"
	exit 0
fi

chmod "$FILE_MODE" "$TMP_PATH"
if ! mv -f "$TMP_PATH" "$CRT_PATH"; then
	log "Error refreshing certificate: Unable to write certificate file!" >&2
	exit 1
fi

log "$CERT_HOST_KEY: Certificate written. Signaling nginx to reload..."
# 憑證已更新，依部署方式選擇一種方式讓 nginx 重新載入憑證（只有實際寫入新憑證時才會執行到這裡）：
#
# 1. nginx 與本 script 在同一台主機或同一個 container：
#    nginx -s reload
#
# 2. 本 script 跑在主機上，nginx 跑在 container（名稱為 nginx）：
#    docker exec nginx nginx -s reload
#    不建議在 container 內使用：需要掛載 docker.sock，等同取得整台主機的控制權
#
# 3. 本 script 跑在另一個 container，且共用 nginx container 的 PID namespace
#    （docker run --pid=container:nginx，或 compose 的 pid: "service:nginx"）：
#    kill -s HUP 1
#    - 共用 PID namespace 後，PID 1 是 nginx master，收到 SIGHUP 等同 nginx -s reload
#    - 若未共用 PID namespace，PID 1 會是本 container 自己的程序，signal 會發錯對象
#    - nginx container 的 PID 1 必須是 nginx 本身（官方 image 即是），或會轉發 signal 的 init（tini、dumb-init）
#      可用 tr '\0' ' ' < /proc/1/cmdline 確認，應看到 nginx: master process ...
#    - 本 container 需以 root 執行（與 nginx master 相同使用者），否則 kill 會因權限不足失敗
#    - 新憑證若載入失敗，nginx 會保留原本的設定繼續運作，不會因此中斷服務

log "$CERT_HOST_KEY: $REMOTE_END. Updated! ✅"
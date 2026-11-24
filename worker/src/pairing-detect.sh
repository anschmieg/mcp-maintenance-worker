detect_host() {
  PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin
  export PATH
  if [ "$(uname -s)" != Linux ]; then
    if [ -n "${pairing_token:-}" ] && [ -n "${claim_url:-}" ]; then
      curl -fsS --max-time 4 -o /dev/null -H "Authorization: Bearer $pairing_token" \
        --data-urlencode 'error=unsupported_platform' "$claim_url" 2>/dev/null || :
    fi
    echo 'PaSTA pairs Linux hosts only. Run a fresh setup command on a Linux host.' >&2
    return 1
  fi
  if ! [ -t 0 ]; then
    echo 'Run this command in an interactive terminal.' >&2
    return 1
  fi
  if ! command -v tailscale >/dev/null 2>&1 || ! address=$(tailscale ip -4 2>/dev/null) || [ -z "$address" ]; then
    echo 'Tailscale is not connected on this machine. Sign in to Tailscale here, then try again.' >&2
    return 1
  fi
  installer=$(mktemp) || return 1
  trap 'rm -f -- "$installer"' 0 HUP INT TERM
  code=$(curl -sS --max-time 20 -o "$installer" -w '%{http_code}' \
    -H "Authorization: Bearer $pairing_token" --data-urlencode "address=$address" "$claim_url") || {
      echo 'Could not reach PaSTA. Check this host’s HTTPS connection and try again.' >&2
      return 1
    }
  if [ "$code" != 200 ]; then
    cat "$installer" >&2
    return 1
  fi
  /bin/sh "$installer"
}

detect_host

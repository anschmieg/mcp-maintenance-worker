detect_host() {
  PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin
  export PATH
  if [ "$(uname -s)" != Linux ]; then
    echo 'Run this command on the Linux host you want to enroll.' >&2
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

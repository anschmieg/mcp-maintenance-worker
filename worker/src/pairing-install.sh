# Per-pairing values are supplied by the Worker above this file.
notify_worker() {
  curl -fsS --max-time 20 -H "Authorization: Bearer $pairing_token" "$@" "$callback_url" >/dev/null
}

note() {
  printf '  %s\n' "$1" >&3
}

pair_host() {
  PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin
  export PATH
  if [ "$(uname -s)" != Linux ]; then
    echo 'Run this command in a terminal on the selected Linux host.' >&2
    return 1
  fi
  if [ "$(id -u)" != 0 ]; then
    echo 'Administrator permission is required. Copy the complete command from setup.' >&2
    return 1
  fi
  if ! (true </dev/tty) 2>/dev/null; then
    echo 'Open an interactive terminal on the selected host and run the setup command again.' >&2
    return 1
  fi
  exec 3<>/dev/tty
  accent=''
  reset=''
  if [ -n "${TERM:-}" ] && [ "$TERM" != dumb ] && [ -z "${NO_COLOR:-}" ]; then
    accent=$(printf '\033[1;36m')
    reset=$(printf '\033[0m')
  fi

  printf '\n  %sPaSTA  /  Pair a host%s\n\n' "$accent" "$reset" >&3
  printf '  Host      %s\n  Account   %s\n\n' "$target_address" "$account" >&3

  if ! tailscale ip -4 | grep -Fxq -- "$target_address"; then
    note 'This machine does not match the selected Tailscale address.'
    note 'Connect to the selected machine and run the command there.'
    return 1
  fi
  fingerprint=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
  case "$fingerprint" in
    SHA256:*) ;;
    *)
      note 'No SSH host key found. Enable OpenSSH Server here, then run the command again.'
      return 1
      ;;
  esac

  if account_uid=$(id -u "$account" 2>/dev/null); then
    if [ "$account_uid" = 0 ]; then
      note 'The dedicated account must be unprivileged.'
      return 1
    fi
    account_action=reused
    primary='Pair using the existing account'
  else
    account_action=created
    primary='Create the dedicated account and pair'
  fi

  while :; do
    printf '  %s1%s  %s\n  2  Show what setup installs\n  3  Cancel\n\n  Choice [3]: ' \
      "$accent" "$reset" "$primary" >&3
    if ! IFS= read -r answer <&3; then answer=''; fi
    case "$answer" in
      1) break ;;
      2)
        printf '\n' >&3
        note 'PaSTA installs one restricted SSH key for the dedicated account.'
        note 'It sends this machine’s SSH fingerprint to the setup page.'
        note 'The next step is a passkey-approved SSH verification.'
        printf '\n' >&3
        ;;
      ''|3)
        if notify_worker --data-urlencode 'account_action=canceled'; then
          note 'Pairing canceled. The setup page will update.'
        else
          note 'Pairing canceled here. Reopen the setup page to start again.'
        fi
        return 1
        ;;
      *) note 'Enter 1, 2, or 3.' ;;
    esac
  done

  printf '\n' >&3
  if [ "$account_action" = created ]; then
    note 'Creating the dedicated account…'
    if ! useradd --system --create-home --home-dir /var/lib/"$account" --shell /bin/sh "$account"; then
      note 'Account creation failed. Check the error above, then rerun the command.'
      return 1
    fi
  fi
  note 'Installing the restricted SSH key…'
  if ! runuser -u "$account" -- /bin/sh -c "$install_command"; then
    note 'Could not install the SSH key. Check the error above, then rerun the command.'
    return 1
  fi
  if ! notify_worker --data-urlencode "fingerprint=$fingerprint" --data-urlencode "account_action=$account_action"; then
    note 'The setup page did not confirm receipt. Check the page before trying again.'
    return 1
  fi
  printf '\n  %sHost paired%s\n  Return to the setup page to verify SSH with your passkey.\n\n' "$accent" "$reset" >&3
}

pair_host

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
  printf '  Host  %s (%s)\n\n' "$target_name" "$target_address" >&3

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

  while :; do
    printf '  %s1%s  Use the dedicated %s account (create if needed)\n' "$accent" "$reset" "$account" >&3
    printf '  2  Use an existing login account\n  3  Show what setup installs\n  4  Cancel\n\n  Choice [4]: ' >&3
    if ! IFS= read -r answer <&3; then answer=''; fi
    case "$answer" in
      1)
        if account_uid=$(id -u "$account" 2>/dev/null); then
          if [ "$account_uid" = 0 ]; then
            note 'The dedicated account must have a nonzero user ID.'
            continue
          fi
          account_action=reused
        else
          account_action=created
        fi
        break
        ;;
      2)
        printf '\n  Existing login name (Enter to go back): ' >&3
        if ! IFS= read -r selected_account <&3 || [ -z "$selected_account" ]; then continue; fi
        case "$selected_account" in
          root|[!a-zA-Z_]*|*[!a-zA-Z0-9_.-]*)
            note 'Enter a valid non-root login name.'
            continue
            ;;
        esac
        if [ "${#selected_account}" -gt 32 ] ||
           ! account_uid=$(id -u "$selected_account" 2>/dev/null) || [ "$account_uid" = 0 ]; then
          note 'Choose an existing login with a nonzero user ID.'
          continue
        fi
        printf '  Install the restricted PaSTA SSH key for %s? [y/N] ' "$selected_account" >&3
        if ! IFS= read -r confirm <&3; then continue; fi
        case "$confirm" in y|Y|yes|YES) ;; *) continue ;; esac
        account="$selected_account"
        account_action=existing
        break
        ;;
      3)
        printf '\n' >&3
        note 'PaSTA installs one restricted SSH key for the account you choose.'
        note 'The key allows only the pairing check and the fixed maintenance operation.'
        note 'Maintenance needs passkey approval and uses the account’s existing sudo policy.'
        note 'It sends this machine’s SSH fingerprint to the setup page.'
        note 'PaSTA checks the restricted SSH connection before adding the host.'
        printf '\n' >&3
        ;;
      ''|4)
        if notify_worker --data-urlencode 'account_action=canceled'; then
          note 'Pairing canceled. The setup page will update.'
        else
          note 'Pairing canceled here. Reopen the setup page to start again.'
        fi
        return 1
        ;;
      *) note 'Enter 1, 2, 3, or 4.' ;;
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
  if ! runuser -u "$account" -- /bin/sh -c "$install_command" pasta-install "$account"; then
    note 'Could not install the SSH key. Check the error above, then rerun the command.'
    return 1
  fi
  if ! notify_worker --data-urlencode "fingerprint=$fingerprint" --data-urlencode "account_action=$account_action" --data-urlencode "account=$account"; then
    note 'The setup page did not confirm receipt. Check the page before trying again.'
    return 1
  fi
  if [ -z "$result_url" ]; then
    note 'SSH key installed. Continue on the setup page.'
    return 0
  fi
  note 'Verifying the restricted SSH connection…'
  count=0
  while [ "$count" -lt 12 ]; do
    result=$(curl -fsS --max-time 4 -H "Authorization: Bearer $pairing_token" "$result_url") || break
    case "$result" in
      verified)
        printf '\n  %sPaired and verified%s\n\n' "$accent" "$reset" >&3
        return 0
        ;;
      verification_failed)
        note 'The key was installed, but SSH verification failed. See the setup page for details and retry.'
        return 1
        ;;
    esac
    count=$((count + 1))
    sleep 2
  done
  note 'SSH verification is still pending. Check the setup page for the result.'
}

pair_host

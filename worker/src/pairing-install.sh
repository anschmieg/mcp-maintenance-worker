# Per-pairing values are supplied by the Worker above this file.
notify_worker() {
  curl -fsS --max-time 20 -H "Authorization: Bearer $pairing_token" "$@" "$callback_url" >/dev/null
}

note() {
  printf '  %s\n' "$1" >&3
}

as_admin() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  else
    sudo -- "$@"
  fi
}

# Both tools write the selection to stderr and draw the menu on stdout.
terminal_menu() {
  "$menu_tool" --title 'PaSTA / Pair a host' "$@" 3>&1 1>&2 2>&3
}

login_accounts() {
  getent passwd | awk -F: -v dedicated="$account" '
    $1 != dedicated && $1 != "root" && $1 ~ /^[A-Za-z_][A-Za-z0-9_.-]*$/ &&
    length($1) <= 32 && $3 > 0 && $7 ~ /^\// && $7 !~ /\/(false|nologin|sync|halt|shutdown)$/ {
      if ($3 >= 1000 && regular_count < 10) regular[++regular_count] = $1
      if ($3 < 1000 && other_count < 10) other[++other_count] = $1
    }
    END {
      for (i = 1; i <= regular_count; i++) print regular[i]
      for (i = 1; i <= other_count && regular_count + i <= 10; i++) print other[i]
    }
  '
}

choose_login() {
  logins=$(login_accounts)
  if [ -n "$menu_tool" ]; then
    set -- + 'Enter another username'
    if [ -n "$logins" ]; then
      while IFS= read -r login; do
        set -- "$@" "$login" ''
      done <<EOF
$logins
EOF
    fi
    choice=$(terminal_menu --default-item + --menu 'Choose a login account' 20 68 11 "$@") || return 1
    case "$choice" in
      +) terminal_menu --inputbox 'Enter an existing login name' 9 60 ;;
      *) printf '%s\n' "$choice" ;;
    esac
    return
  fi
  if [ -n "$logins" ]; then
    note 'Available logins (up to 10):'
    while IFS= read -r login; do
      printf '    %s\n' "$login" >&3
    done <<EOF
$logins
EOF
  else
    note 'No login accounts were listed. You can still enter a username.'
  fi
  printf '\n  Existing login name (Enter to go back): ' >&3
  IFS= read -r login && printf '%s\n' "$login"
}

pair_host() {
  PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin
  export PATH
  if [ "$(uname -s)" != Linux ]; then
    echo 'Run this command in a terminal on the selected Linux host.' >&2
    return 1
  fi
  if ! [ -t 0 ]; then
    echo 'Open an interactive terminal on the selected host and run the setup command again.' >&2
    return 1
  fi
  exec 3>&2
  menu_tool=''
  if [ -t 2 ] && [ -n "${TERM:-}" ] && [ "$TERM" != dumb ]; then
    terminal_size=$(stty size 2>/dev/null) || terminal_size=''
    set -- $terminal_size
    if [ "$#" = 2 ] && [ "$1" -ge 22 ] && [ "$2" -ge 72 ]; then
      for candidate in whiptail dialog; do
        if command -v "$candidate" >/dev/null && "$candidate" --version >/dev/null 2>&1; then
          menu_tool=$candidate
          break
        fi
      done
    fi
  fi
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
  while :; do
    if [ -n "$menu_tool" ]; then
      answer=$(terminal_menu --default-item 4 --menu "Host: $target_name ($target_address)" 16 70 4 \
        1 "Use the dedicated $account account (create if needed)" \
        2 'Use an existing login account' 3 'Show what setup installs' 4 'Cancel') || answer=4
    else
      printf '  %s1%s  Use the dedicated %s account (create if needed)\n' "$accent" "$reset" "$account" >&3
      printf '  2  Use an existing login account\n  3  Show what setup installs\n  4  Cancel\n\n  Choice [4]: ' >&3
      if ! IFS= read -r answer; then answer=''; fi
    fi
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
        if ! selected_account=$(choose_login) || [ -z "$selected_account" ]; then continue; fi
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
        if [ -n "$menu_tool" ]; then
          "$menu_tool" --title 'PaSTA / Pair a host' --defaultno --yesno \
            "Install the restricted PaSTA SSH key for $selected_account?" 9 66 >&2 || continue
        else
          printf '  Install the restricted PaSTA SSH key for %s? [y/N] ' "$selected_account" >&3
          if ! IFS= read -r confirm; then continue; fi
          case "$confirm" in y|Y|yes|YES) ;; *) continue ;; esac
        fi
        account="$selected_account"
        account_action=existing
        break
        ;;
      3)
        details='PaSTA installs one restricted SSH key for the account you choose.
The key allows only the pairing check and the fixed maintenance operation.
Maintenance needs passkey approval and uses the account’s existing sudo policy.
PaSTA sends this machine’s SSH fingerprint to the Worker and checks the restricted SSH connection.'
        if [ -n "$menu_tool" ]; then
          "$menu_tool" --title 'PaSTA / What setup installs' --msgbox "$details" 14 68 >&2
        else
          printf '\n%s\n\n' "$details" >&3
        fi
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
  fingerprint=$(as_admin ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
  case "$fingerprint" in
    SHA256:*) ;;
    *)
      note 'No SSH host key found. Enable OpenSSH Server here, then run the command again.'
      return 1
      ;;
  esac

  if [ "$account_action" = created ]; then
    note 'Creating the dedicated account…'
    if ! as_admin useradd --system --create-home --home-dir /var/lib/"$account" --shell /bin/sh "$account"; then
      note 'Account creation failed. Check the error above, then rerun the command.'
      return 1
    fi
  fi
  note 'Installing the restricted SSH key…'
  if ! as_admin runuser -u "$account" -- /bin/sh -c "$install_command" pasta-install "$account"; then
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

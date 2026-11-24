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

# Dialog tools return a tag. Gum and fzf return the displayed label.
terminal_menu() {
  menu_prompt=$1
  menu_default=$2
  menu_height=$3
  menu_width=$4
  menu_rows=$5
  shift 5
  case "$menu_tool" in
    whiptail|dialog)
      "$menu_tool" --title 'PaSTA / Pair a host' --default-item "$menu_default" \
        --menu "$menu_prompt" "$menu_height" "$menu_width" "$menu_rows" "$@" 3>&1 1>&2 2>&3
      return
      ;;
  esac

  # Put the safe default first in pickers that focus the first result.
  labels=$(
    other_labels=''
    while [ "$#" -gt 0 ]; do
      label=${2:-$1}
      if [ "$1" = "$menu_default" ]; then
        default_label=$label
      else
        other_labels="$other_labels
$label"
      fi
      shift 2
    done
    printf '%s\n' "$default_label$other_labels"
  )
  case "$menu_tool" in
    gum)
      picked=$(printf '%s\n' "$labels" | gum filter --limit 1 --header "$menu_prompt") || return 1
      ;;
    fzf)
      picked=$(printf '%s\n' "$labels" | FZF_DEFAULT_OPTS= FZF_DEFAULT_OPTS_FILE= \
        fzf --no-multi --no-sort --reverse --header "$menu_prompt") || return 1
      ;;
  esac
  while [ "$#" -gt 0 ]; do
    if [ "$picked" = "${2:-$1}" ]; then
      printf '%s\n' "$1"
      return 0
    fi
    shift 2
  done
  return 1
}

confirm_account() {
  case "$menu_tool" in
    whiptail|dialog)
      "$menu_tool" --title 'PaSTA / Pair a host' --defaultno --yesno "$1" 9 66 >&2
      ;;
    gum)
      gum confirm --default=false "$1" >&2
      ;;
    *)
      printf '  %s [y/N] ' "$1" >&3
      IFS= read -r confirm || return 1
      case "$confirm" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
      ;;
  esac
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
    choice=$(terminal_menu 'Choose a login account' + 20 68 11 "$@") || return 1
    case "$choice" in
      +)
        case "$menu_tool" in
          whiptail|dialog)
            "$menu_tool" --title 'PaSTA / Pair a host' --inputbox 'Enter an existing login name' 9 60 3>&1 1>&2 2>&3
            ;;
          gum) gum input --prompt 'Existing login name: ' ;;
          fzf) read_login ;;
        esac
        ;;
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
  read_login
}

read_login() {
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
      for candidate in gum whiptail dialog fzf; do
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
  if [ "${command_execution:-no}" = yes ]; then
    if [ ! -x /bin/bash ]; then
      note 'Install Bash at /bin/bash before pairing this host for command execution.'
      return 1
    fi
    note 'PaSTA can run approved Bash commands with the permissions of the selected account.'
    note 'The PaSTA Worker holds the SSH key for this access. Choose a dedicated account with minimal permissions.'
  fi
  while :; do
    if [ -n "$menu_tool" ]; then
      answer=$(terminal_menu "Host: $target_name ($target_address)" 1 16 70 4 \
        1 "Use the dedicated $account account (create if needed)" \
        2 'Use an existing login account' 3 'Show what setup installs' 4 'Cancel') || answer=4
    else
      printf '  %s1%s  Use the dedicated %s account (create if needed)\n' "$accent" "$reset" "$account" >&3
      printf '  2  Use an existing login account\n  3  Show what setup installs\n  4  Cancel\n\n  Choice [1]: ' >&3
      if ! IFS= read -r answer; then return 1; fi
      answer=${answer:-1}
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
        confirm_account "Install the restricted PaSTA SSH key for $selected_account?" || continue
        account="$selected_account"
        account_action=existing
        break
        ;;
      3)
        details='PaSTA installs one restricted SSH key for the account you choose.
PaSTA sends this machine’s SSH fingerprint to the Worker and checks the restricted SSH connection.'
        if [ "${command_execution:-no}" = yes ]; then
          details="$details
The Worker holds the key, which can run Bash commands with this account’s permissions.
The Worker requires passkey approval before it sends a command."
        else
          details="$details
This key only allows the pairing check and fixed service restart."
        fi
        case "$menu_tool" in
          whiptail|dialog)
            "$menu_tool" --title 'PaSTA / What setup installs' --msgbox "$details" 14 68 >&2
            ;;
          gum|fzf)
            terminal_menu "$details" back 14 68 1 back 'Back to setup' >/dev/null || :
            ;;
          *) printf '\n%s\n\n' "$details" >&3 ;;
        esac
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
  if [ -n "${approval_gate:-}" ]; then
    gate_dir="/var/lib/pasta-approval/$account"
    if ! as_admin test -x /usr/bin/python3 || ! as_admin test -x /usr/bin/openssl ||
       ! as_admin test -x /usr/sbin/visudo; then
      note 'Command approval requires Python 3, OpenSSL and sudo.'
      return 1
    fi
    if ! as_admin install -d -m 0755 /usr/local/libexec ||
       ! as_admin install -d -m 0700 "$gate_dir" "$gate_dir/used" ||
       ! printf '%s\n' "$approval_gate" | as_admin install -m 0644 /dev/stdin /usr/local/libexec/pasta-approval.py ||
       ! printf '%s\n' "$approval_public_key" | as_admin install -m 0600 /dev/stdin "$gate_dir/public.pem" ||
       ! printf '%s\n' "$approval_target" | as_admin install -m 0600 /dev/stdin "$gate_dir/target.json"; then
      note 'Could not install the approval verifier.'
      return 1
    fi
    sudo_rule="$account ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/pasta-approval.py"
    if ! printf '%s\n' "$sudo_rule" | as_admin /usr/sbin/visudo -c -f - >/dev/null ||
       ! printf '%s\n' "$sudo_rule" | as_admin install -m 0440 /dev/stdin "/etc/sudoers.d/pasta-approval-$(printf %s "$account" | tr . _)"; then
      note 'Could not configure the approval verifier in sudo.'
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

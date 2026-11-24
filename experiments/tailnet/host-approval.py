"""Verify and consume a PaSTA approval in a gate-owned state directory."""
import base64
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def consume(token, public_key, state, *, enrollment, host, account, now=None):
    if len(token) > 24000 or token.count(".") != 1:
        raise ValueError("Invalid approval envelope")
    encoded, signature = token.split(".")
    payload = _decode(encoded)
    signature = _decode(signature)
    with tempfile.TemporaryDirectory() as scratch:
        data = Path(scratch, "payload")
        sig = Path(scratch, "signature")
        data.write_bytes(payload)
        sig.write_bytes(signature)
        result = subprocess.run(
            ["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
             str(public_key), "-rawin", "-in", str(data), "-sigfile", str(sig)],
            capture_output=True, timeout=3,
        )
    if result.returncode:
        raise ValueError("Approval signature failed")
    approval = json.loads(payload)
    now = int(time.time()) if now is None else now
    issued, expires = approval["issued"], approval["expires"]
    if (approval["version"] != 1 or approval["enrollment"] != enrollment
            or approval["host"] != host or approval["account"] != account
            or type(issued) is not int or type(expires) is not int
            or not issued <= now < expires <= issued + 30):
        raise ValueError("Approval target or validity period failed")
    command = approval["command"]
    if not isinstance(command, str) or not 0 < len(command.encode()) <= 4096 or "\0" in command:
        raise ValueError("Invalid approved command")
    job = str(uuid.UUID(approval["job"]))
    Path(state, job).mkdir(mode=0o700)
    directory = os.open(state, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return command


def _decode(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def main():
    import pwd
    import signal
    import re
    import sys

    account = os.environ.get("SUDO_USER", "")
    if os.geteuid() != 0 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", account):
        return 126
    try:
        user = pwd.getpwnam(account)
        if user.pw_uid == 0:
            return 126
        directory = Path("/var/lib/pasta-approval", account)
        config = json.loads((directory / "target.json").read_text())
        signal.alarm(5)
        token = sys.stdin.buffer.read(24001).decode("ascii")
        signal.alarm(0)
        command = consume(token, directory / "public.pem", directory / "used",
                          enrollment=config["enrollment"], host=config["host"], account=account)
        os.initgroups(account, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        os.chdir(user.pw_dir)
        descriptor = os.open("/dev/null", os.O_RDONLY)
        os.dup2(descriptor, 0)
        os.close(descriptor)
        os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-c", command], {
            "HOME": user.pw_dir, "USER": account, "LOGNAME": account,
            "PATH": "/usr/bin:/bin", "SHELL": "/bin/bash",
        })
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        print("PaSTA approval rejected or could not be started.", file=sys.stderr)
    return 126


if __name__ == "__main__":
    raise SystemExit(main())

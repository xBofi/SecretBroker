"""SSH action checks against an in-process paramiko server.

Run with:  .venv\\Scripts\\python.exe tests\\test_ssh.py
"""

import os
import socket
import sys
import tempfile
import threading

HOME = tempfile.mkdtemp(prefix="secretbroker-ssh-test-")
os.environ["SECRETBROKER_HOME"] = HOME

import io  # noqa: E402

import paramiko  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from pathlib import Path  # noqa: E402

from secretbroker import actions  # noqa: E402
from secretbroker.actions import ssh_exec  # noqa: E402

KNOWN_HOSTS = Path(HOME) / "known_hosts"
actions.configure(KNOWN_HOSTS)

PASSWORD = "Sup3r-Secret-SSH-pass"


def new_key():
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode()))


HOST_KEY = new_key()


class FakeServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("deploy", PASSWORD) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        def run():
            command_text = command.decode()
            stdin = b""
            while True:  # read until client shuts down its write side
                data = channel.recv(1024)
                if not data:
                    break
                stdin += data
            channel.sendall(f"cmd={command_text}\nstdin={stdin.decode()!r}\n".encode())
            channel.sendall_stderr(b"leak attempt: " + PASSWORD.encode() + b"\n")
            channel.send_exit_status(0)
            channel.close()
        threading.Thread(target=run, daemon=True).start()
        return True


def serve(listener):
    while True:
        conn, _ = listener.accept()
        transport = paramiko.Transport(conn)
        transport.add_server_key(HOST_KEY)
        transport.start_server(server=FakeServer())


def main():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    threading.Thread(target=serve, args=(listener,), daemon=True).start()
    port = listener.getsockname()[1]
    entry = {"id": "test-ssh", "template": "ssh", "description": "",
             "fields": {"host": "127.0.0.1", "port": str(port), "username": "deploy", "auth_method": "password", "password": PASSWORD},
             "policy": {}}

    failures = 0

    def check(condition, message):
        nonlocal failures
        print(("  OK   " if condition else "  FAIL ") + message)
        failures += not condition

    result = ssh_exec(entry, {"command": "uptime"})
    check(result["exit_code"] == 0 and "cmd=uptime" in result["stdout"], "command runs over SSH")
    check("note" in result and KNOWN_HOSTS.read_text().strip(), "host key recorded on first use")
    check(PASSWORD not in str(result) and "[REDACTED:test-ssh]" in result["stderr"], "password redacted from stderr")

    result = ssh_exec(entry, {"command": "systemctl restart nginx", "sudo": True})
    check("sudo -k -S -p '' sh -c 'systemctl restart nginx'" in result["stdout"], "sudo wrapper applied")
    check("stdin='[REDACTED:test-ssh]\\n'" in result["stdout"], "password fed to sudo via stdin, redacted in output")
    check("note" not in result, "known host key not re-recorded")

    other_key = new_key()
    hosts = paramiko.HostKeys(str(KNOWN_HOSTS))
    hosts.add(f"[127.0.0.1]:{port}", "ssh-ed25519", other_key)
    hosts.save(str(KNOWN_HOSTS))
    try:
        ssh_exec(entry, {"command": "id"})
        check(False, "changed host key rejected")
    except paramiko.BadHostKeyException:
        check(True, "changed host key rejected")

    print("\nALL PASSED" if not failures else f"\n{failures} FAILED")
    sys.exit(1 if failures else 0)



if __name__ == "__main__":
    main()

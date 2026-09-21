"""Offline PTY fixture: no node, network, wallet, signing or broadcast.

Build: cargo test -p urma-cli --test git_terminal --no-run
Run: python3 urma-cli/tests/git_ui_demo.py target/debug/deps/git_terminal-<hash>
"""
import errno
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def run(binary, width, answer=None, no_color=False, live=False, cli_args=None, interrupt=False):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 28, width, 0, 0))
    env = dict(os.environ, TERM="xterm-256color")
    env.pop("NO_COLOR", None)
    env.pop("CLICOLOR_FORCE", None)
    if no_color:
        env["NO_COLOR"] = "1"
    if answer is not None:
        env["URMA_UI_FIXTURE"] = "confirm"
    process = subprocess.Popen(
        [binary] + (cli_args if cli_args is not None else ["--exact", "ui_fixture", "--ignored", "--nocapture"]),
        stdin=slave, stdout=slave, stderr=slave, env=env, close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                output.extend(data)
                if live:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                if answer is not None and not sent and b"[y/N]" in output:
                    os.write(master, answer.encode() + b"\n")
                    sent = True
                if interrupt and not sent and b"6 prepared" in output and b"Target confirmed" in output:
                    process.send_signal(signal.SIGINT)
                    sent = True
            elif process.poll() is not None:
                break
        assert process.wait(timeout=2) == (1 if interrupt else 0), output.decode(errors="replace")
        if interrupt:
            assert sent, "watch never rendered its initial observations"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
    return output.decode()


def check(binary):
    for width, no_color in [(90, False), (40, True)]:
        raw = run(binary, width, no_color=no_color)
        plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw)
        for text in ["Signing records", "2/4", "Receiving payload bytes", "256/512", "6/6", "0/6", "Network", "Confirmed", "Fixture log", "Fixture stopped"]:
            assert text in plain, (width, text, plain)
        assert "100%" not in plain and "ETA" not in plain
        assert "Target confirmed" in plain
        frames = screens(raw, width)
        mempool = next(frame for frame in frames if any("Network" in line and "6/6" in line for line in frame) and any("Confirmed" in line and "0/6" in line for line in frame))
        assert all(len(line) <= width for line in mempool)
        assert not any("Network" in line or "Confirmed" in line for line in frames[-1]), frames[-1]
        assert "\x1b[" in raw, "fixture did not exercise redraw"
        if no_color:
            assert not re.search(r"\x1b\[[0-9;]*m", raw), raw
        # Clearing the active bars must precede the final error/interruption text.
        tail = raw.split("Fixture stopped", 1)[1]
        assert not re.search(r"\x1b\[[0-9;]*[AK]", tail), tail
    for answer, expected in [("y", True), ("Y", True), ("yes", True), (" yes ", True), ("", False), ("n", False), ("YES", False), ("Yes", False)]:
        raw = run(binary, 80, answer=answer, no_color=True)
        assert f"accepted={str(expected).lower()}" in raw, (answer, raw)
    print("PTY: 90/40 columns, NO_COLOR, redraw, cleanup, exact confirmation responses passed")


def screens(raw, width):
    """Replay the small ANSI subset emitted by indicatif, including autowrap."""
    rows = {}
    row = column = 0
    frames = []
    for token in re.split(r"(\x1b\[[0-9;?]*[A-Za-z])", raw):
        if token.startswith("\x1b["):
            action = token[-1]
            argument = token[2:-1]
            count = int(argument or "1") if argument.isdigit() or not argument else 1
            if action == "A":
                frames.append(["".join(rows[index]).rstrip() for index in sorted(rows)])
                row = max(0, row - count)
                column = min(column, width - 1)
            elif action == "B":
                row += count
                column = min(column, width - 1)
            elif action == "K":
                line = rows.setdefault(row, [" "] * width)
                if argument == "2":
                    rows[row] = [" "] * width
                else:
                    line[column:] = [" "] * (width - column)
            elif action not in ("m", "h", "l"):
                raise AssertionError(f"unsupported terminal control: {token!r}")
            continue
        for char in token:
            if char == "\r":
                column = 0
            elif char == "\n":
                row += 1
            elif char == "\x08":
                column = max(0, column - 1)
            else:
                if column >= width:
                    row += 1
                    column = 0
                rows.setdefault(row, [" "] * width)[column] = char
                column += 1
    frames.append(["".join(rows[index]).rstrip() for index in sorted(rows)])
    return frames


if __name__ == "__main__":
    if "--watch-check" in sys.argv:
        raw = run(sys.argv[1], 90, cli_args=sys.argv[3:], interrupt=True)
        assert "interrupted; target not reached; exact plan remains resumable" in raw, raw
        tail = raw.split("interrupted;", 1)[1]
        assert not re.search(r"\x1b\[[0-9;]*[AK]", tail), tail
        print("Watch Ctrl-C: cleared bars, exit 1, resumable plan")
    elif "--machine-check" in sys.argv:
        raw = run(sys.argv[1], 90, cli_args=sys.argv[3:])
        assert "\x1b" not in raw, raw
        assert "6 confirmed" in raw, raw
        print("JSON mode in PTY: no ANSI or interactive progress")
    elif "--snapshots" in sys.argv:
        for width in (90, 40):
            frames = screens(run(sys.argv[1], width, no_color=True), width)
            frame = next(frame for frame in reversed(frames) if any("Network" in line and "6/6" in line for line in frame) and any("Confirmed" in line and "0/6" in line for line in frame))
            print(f"\nOffline fixture, {width} columns:")
            print("\n".join(line for line in frame if line))
    elif "--check" in sys.argv:
        check(sys.argv[1])
    else:
        run(sys.argv[1], 90, live=True)

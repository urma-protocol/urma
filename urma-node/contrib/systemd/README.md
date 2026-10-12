# Linux user-systemd template

[urma-node.service.example](urma-node.service.example) runs an already supplied
`urma-node` binary in the foreground as the user owning the archive. This is a
manual template, with no installer or automatic startup. Every `REPLACE`
placeholder must be edited before use; the example paths and port deliberately
cannot form a working invocation as supplied. It creates no token, config,
transport key or header bootstrap on the operator's behalf.

## Prepare an operator-owned copy

Choose absolute paths for the binary, archive directory, JSON archive config
and existing bearer-token file. Replace `REPLACE_PORT` with an available numeric
TCP port from 1 through 65535, retaining the explicit `127.0.0.1` loopback bind.
Consumers must use this same endpoint and token. Do not put the token itself in
the unit, command arguments or an environment variable.

The config must explicitly identify the chain, application-start height/hash
and retention mode. It must match an existing archive's persisted identity;
changing the unit is not an archive migration. Keep writable archive state on
a local filesystem under this user, and use one owner process. The archive lock
rejects a second writer; do not run the archive-opening `urma-node status` as a
startup check alongside the service. Authenticated API clients inspect a running
service without opening its database.

Prepare a private regular token file containing the existing 64-hex bearer
token, accessible only to the operator (for example mode `0600`). Keep config,
bootstrap and key inputs under operator control. `UMask=0077` limits new files'
permissions; it does not repair existing permissions or replace input validation.
Binary installation and explicit secret/config preparation remain separate
operator actions described in the [Node README](../../README.md).

`ExecStart` is a systemd argument list, not a shell command. Keep the complete
binary path and each path argument quoted with double quotes, including paths
with spaces. A literal quote or backslash needs systemd escaping (`\"` or `\\`);
literal `%` and `$` in arguments need `%%` and `$$` respectively. Shell quoting,
`~`, command substitution, pipes and redirection do not provide path expansion
here. Use literal absolute paths, not `$HOME`, `%h` or a shell wrapper. Consult
the local `systemd.service(5)` command-line rules and `systemd.syntax(7)` when
editing unusual paths.

After reviewing an edited copy, choose the actual user-unit directory used by
your user manager (commonly `$HOME/.config/systemd/user`). Create that directory
manually if needed. The following are operator instructions, not actions
performed by this template; fill both absolute paths before copying:

```sh
cp -- "/REPLACE/ABSOLUTE/PATH/edited-urma-node.service" "/REPLACE/ABSOLUTE/PATH/user-unit-directory/urma-node.service"
systemctl --user daemon-reload
systemctl --user start urma-node.service
systemctl --user status urma-node.service
```

There is no `[Install]` section or target attachment: each start is explicit.
The user manager must already be running. Neither installing the file nor
starting it promises survival after logout or across user-manager shutdown;
session lifetime is determined by the host. No boot/login activation or change
to user-manager lifetime is part of this procedure. `Restart=no` also leaves a
failed or exited process stopped until another explicit start.

`Type=simple` means the main process remains in the foreground. A successful
start job is not an HTTP readiness acknowledgement or proof of healthy state.
Check the reported listening address and an authenticated local status response
before relying on the service. This template supplies no socket activation,
PID file or readiness notification.

## Stop and shutdown limits

```sh
systemctl --user stop urma-node.service
```

Stopping sends `SIGTERM` to the service control group. The standalone binary
requests the existing cooperative shutdown and waits for its Service worker
and any URMA overlay workers before returning. Wait for process exit before
reopening the archive. No HTTP shutdown helper is used: an HTTP acknowledgement
would establish only that a stop was requested, not that workers had joined.

`TimeoutStopSec=30s` bounds the supervisor's wait. With `SendSIGKILL=yes`, an
unfinished stop is forcibly terminated after that timeout. This is a fallback,
not a guarantee that source I/O, HTTP handling or SQLite work finishes within
30 seconds, and it is not a graceful join. Choose a different finite stop budget
deliberately if needed; never infer successful cleanup from a forced termination.
Normal database recovery checks still apply on the next explicit start.

The signal implementation in base `10d953d770f0b5f614caf36accce2311e45a287e`
passed dedicated Linux process tests: SIGINT/SIGTERM/SIGHUP normal exit and
archive reopen, SIGTERM with an explicit offline overlay, and embedded worker
shutdown. Those tests do not establish a tested systemd installation or
supervised shutdown.

## Explicit network opt-ins

The supplied `ExecStart` omits `--p2p` and `--peer-key`: it serves available local
state without starting either peer transport or background synchronization.
There is no network-online dependency or peer default in this unit.

To opt into the Litecoin source and background maintenance, append these
arguments to the same `ExecStart` after selecting and preparing the bootstrap:

```text
--p2p --header-bootstrap "/REPLACE/ABSOLUTE/PATH/bootstrap.json"
```

The bootstrap must match the configured chain and permitted application start;
its checkpoint height and chain membership are explicit operator trust choices.
The [Node README](../../README.md) specifies the header-context format and
validation limits. Do not substitute an invented genesis or start point. The
underlying Litecoin source retains its existing discovery/DNS policy: this edit
does not promise DNS-free networking or select new peer policy.

The URMA overlay is a separate opt-in, using an already created private transport
identity. Append this argument only when that transport is wanted:

```text
--peer-key "/REPLACE/ABSOLUTE/PATH/transport.key"
```

Without an overlay listener it is outbound-only. If desired, explicitly append
`--urma-listen "REPLACE_IP:REPLACE_PORT"` with the chosen numeric bind (use
`[IPv6]:PORT` for IPv6), and/or repeated
`--urma-peer "/ip4/REPLACE_IP/tcp/REPLACE_PORT/p2p/REPLACE_PEER_ID"` routing hints.
The listener is separate from the authenticated loopback HTTP endpoint. Review
exposure before selecting its bind. With the key opt-in, the archive's saved
`peers.json` is also read; identities are routing hints, not chain authorities.
The transport key is not a wallet or decryption key. No key or peer entry is
created implicitly by this template.

Optional resource flags remain the binary's explicit configuration:
`--cache-bytes` is a soft logical multipart-cache target, not a disk quota;
`--max-object-bytes`, `--max-object-nodes` and `--object-timeout-seconds` bound
background object attempts. These do not impose a hard deadline on entered
I/O or SQL. The config's retention policy and existing CLI validation remain
unchanged.

## Static verification

A separately authorized check can copy this template into an owned temporary
directory as `urma-node.service`, substitute all paths with owned fixtures and
the executable path with an existing inert executable such as `/usr/bin/true`,
and set the endpoint to an owned loopback example such as `127.0.0.1:28331`.
The data, config and token placeholders would reference only owned fixture paths,
without using real credentials or an archive. Create owned temporary home/XDG
directories (runtime directory mode `0700`) and restrict `SYSTEMD_UNIT_PATH` to
the fixture and vendor unit directories, excluding real user units. The
command, with all paths substituted, is:

```sh
env -i HOME="/REPLACE/OWNED-TEMP/home" XDG_CONFIG_HOME="/REPLACE/OWNED-TEMP/config" XDG_DATA_HOME="/REPLACE/OWNED-TEMP/data" XDG_RUNTIME_DIR="/REPLACE/OWNED-TEMP/runtime" SYSTEMD_UNIT_PATH="/REPLACE/OWNED-TEMP/units:/usr/lib/systemd/user:/lib/systemd/user" /usr/bin/systemd-analyze --user --generators=no --man=no verify "/REPLACE/OWNED-TEMP/units/urma-node.service"
```

Adjust vendor and executable locations to the host; do not enable unit generators.
Verification parses and checks the unit without starting the executable. Bound
the verifier process and capture its exit status and diagnostics; do not load the
fixture into a real user manager. This checks unit syntax only, not URMA
arguments, authentication, signal behavior or graceful shutdown.

This procedure was run with systemd 262 against template revision
`362d00a03af3bd7d78804c44520d4a3238be179c` and returned exit status 0 with no
template diagnostics. It was not warning-free: the long temporary runtime path
exceeded Unix-socket address limits in vendor units, producing address and
dependency diagnostics. Use a short owned runtime-directory path when repeating
the check. No executable was started and no unit was installed in a user manager.

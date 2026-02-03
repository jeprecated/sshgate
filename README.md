# sshgate

`sshgate` is a human-gated SSH proxy for one-off sessions. A human explicitly opens an SSH control connection, and only then can an agent run commands through that already-approved session. This creates a simple trust barrier: no human approval, no agent access.

## Why

- Keep SSH access human-controlled while still enabling agent automation.
- Avoid long-lived daemons or permanent tunnels; sessions are ephemeral.
- Reduce command-injection risk by defaulting to argument-based execution.

## How it works

1. Human opens the gate (foreground SSH control connection).
2. Agent runs commands through the open gate.
3. Human closes the gate.

The open session holds the terminal and logs each command the agent runs.

## Install (devbox)

```sh
devbox init
devbox add go
```

## Build

```sh
devbox run -- go build -o sshgate
```

## Quick start

Human terminal:

```sh
./sshgate init
./sshgate open user@host
```

Agent terminal:

```sh
./sshgate status
./sshgate run uname -a
```

Human terminal (when done):

```sh
./sshgate close
```

## Agent usage

Agents are only allowed to use:

- `sshgate status`
- `sshgate run COMMAND [ARG...]`

For shell operators like `&&`, use a quoted command string:

```sh
sshgate run "ls && pwd"
```

## Security notes

- The SSH control socket and session state live in a per-user runtime directory with 0700 perms.
- The access password hash is stored in `~/.sshgate/access` with 0600 perms.
- `open` runs in the foreground (no daemonization) and cleanly exits on close.
- Exit codes from remote commands are propagated to the caller.

## Troubleshooting

- `no active session`: A human must open the gate first.
- Host visibility: `status` prints `active` unless the session was opened with `--reveal-host`.

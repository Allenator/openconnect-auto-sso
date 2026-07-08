# Tests

Unit tests for the Python modules and the POSIX-sh scripts. Everything runs under **pytest** (the shell tests shell out to `sh`), so one command runs the whole suite.

## Run

```sh
./tests/run.sh              # = .venv/bin/python -m pytest
./tests/run.sh -k dnsroute  # a subset (args pass through to pytest)
uv run pytest               # equivalent, if you use uv
```

Requires the project venv (`uv sync`). No root, no network, and no real routes/DNS are touched — `/sbin/route` is mocked and the resolver sweep is pointed at a temp dir.

## Layout

| File | Covers |
|---|---|
| `test_dnsroute.py` | `src/dnsroute.py`: route injection, dedup, failure cooldown, the in-flight fork-storm guard, SVCB hints, servfail-vs-silence. |
| `test_loadconfig.py` | `src/loadconfig.py`: the `via_vpn` classifier (rejecting metacharacter/typo entries), hostname/IP validators, and the CLI (required/unknown keys, shell-quoting). |
| `test_shell.py` | `bin/vpnc-slice` (`@server` expansion + unsafe-domain filtering, resolver sweep incl. the keep-list) and `install-autostart.sh` (`dir_is_safe` + `verify_safe_ancestors`, the NOPASSWD-helper path guard). macOS-only (skipped elsewhere: BSD `stat -f`, `/etc/resolver`). |

## How the shell tests reach the functions

The scripts run their real logic on `exec`/dispatch, so tests can't just run them. Each script has a test-only seam, all unreachable on the privileged path: the `OC_PROJ`/`RESOLVER_DIR` overrides are read only when NOT root (`bin/vpnc-slice`) or only under `OC_INSTALL_TEST=1` (`install-autostart.sh`), so a leaked env var can't redirect the root-run code — independent of any sudoers `env_keep`. (Sudo also strips the env, and every override defaults to the real value; that is now just defense in depth.)

- `OC_VPNC_SLICE_TEST=1` / `OC_INSTALL_TEST=1` — source-guards that stop the script before its main body, leaving only the functions defined.
- `OC_PROJ` — points `$PROJ`/`$proj` at the repo when sourced (normally derived from `$0`). Honored only off the privileged path: `bin/vpnc-slice` reads it only when NOT root (`id -u` != 0), and `install-autostart.sh` only under `OC_INSTALL_TEST=1`.
- `RESOLVER_DIR` — where `bin/vpnc-slice` reads/writes resolver files (default `/etc/resolver`); tests point it at a temp dir. Honored only when NOT root; a root `bin/vpnc-slice` forces `/etc/resolver` and ignores the override.

`libexec/vpn-teardown` is intentionally left hermetic (no seam — it's the root-owned NOPASSWD helper); it's tested only as a black-box subprocess with a PATH-stubbed `pgrep`, and its kill path is not exercised (it would signal real PIDs).

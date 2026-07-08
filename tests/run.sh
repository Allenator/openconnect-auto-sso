#!/bin/sh
# Run the whole test suite (Python + POSIX-sh, all under pytest). Any extra args are
# passed through to pytest, e.g. ./tests/run.sh -k dnsroute -v
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
exec "$repo/.venv/bin/python" -m pytest "$@"

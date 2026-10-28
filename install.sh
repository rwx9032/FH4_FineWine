#!/bin/sh
# Offline CLI. Use ./install.sh check ... before an explicit install.
exec python3 "$(dirname "$0")/tools/fh4.py" "$@"

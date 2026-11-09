#!/bin/sh
# Only the plugin's own status file is changed; stopping is handled by the manager.
set -eu
cd "$(dirname "$0")"
status_tmp=".status.$$"
trap 'rm -f "$status_tmp"; exit 0' HUP INT TERM
trap 'rm -f "$status_tmp"' EXIT
while :; do
    awk '{printf "{\"uptime_seconds\":%s}\n", $1; exit}' /proc/uptime > "$status_tmp"
    mv -f "$status_tmp" status.json
    sleep 60
done

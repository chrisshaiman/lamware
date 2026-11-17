#!/bin/bash
# ADR-031 phase 0: start, stop or check the lamware-group access measurement.
# On the host, as root:   sudo bash flow-measure.sh start|stop|status
# fatrace (Ubuntu universe, installed for this measurement and removed by `stop`)
# reports every file open/read/write system-wide; flow-reader.py keeps the non-root
# ones under the lamware group's trees and writes hourly counts to $OUT. Runs as a
# transient systemd unit: a process started over ssh dies at logout on this host.
set -euo pipefail
OUT=/root/flow-measure; UNIT=lamware-flow-measure; HERE=$(cd "$(dirname "$0")" && pwd)
case "${1:-}" in
  start)
    command -v fatrace >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q fatrace
    install -d -m 0700 "$OUT"
    install -m 0700 "$HERE/flow-reader.py" "$OUT/flow-reader.py"
    systemd-run --unit="$UNIT" --collect -p StandardError="append:$OUT/flow.err" \
      /bin/bash -c "set -o pipefail; exec fatrace -t -f ORW | /usr/bin/python3 -I $OUT/flow-reader.py $OUT"
    sleep 5; systemctl is-active "$UNIT" && echo "measuring; hourly counts in $OUT" ;;
  stop)
    systemctl stop "$UNIT" || true
    sleep 2; ls -l "$OUT"/flow-*.json | tail -3
    DEBIAN_FRONTEND=noninteractive apt-get remove -y -q fatrace >/dev/null && echo "fatrace removed" ;;
  status) systemctl status "$UNIT" --no-pager | head -6; ls "$OUT" | tail -5 ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac

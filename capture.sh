#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="0.2.0"
DURATION="${DURATION:-300}"
BLE_DURATION="${BLE_DURATION:-45}"
SERIAL_DURATION="${SERIAL_DURATION:-12}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$PWD/rtk3-captures}"
TARGET_IP="${TARGET_IP:-}"
NETWORK_IFACE="${NETWORK_IFACE:-}"
SERIAL_DEVICES="${SERIAL_DEVICES:-auto}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
RUN_NMAP="${RUN_NMAP:-1}"
RUN_BLE="${RUN_BLE:-1}"
RUN_SERIAL="${RUN_SERIAL:-1}"
RUN_PCAP="${RUN_PCAP:-1}"
BAUD_RATES=(9600 19200 38400 57600 115200 230400 460800 921600)
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || echo unknown)"
OUT="$OUTPUT_ROOT/${STAMP}-${HOSTNAME_SHORT}"
RAW="$OUT/raw"
PIDS=()
mkdir -p "$RAW"
exec > >(tee -a "$OUT/capture.log") 2>&1

log(){ printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
cleanup(){ for p in "${PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null || true; done; sleep 1; for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

if [[ $EUID -ne 0 ]]; then
  exec sudo --preserve-env=DURATION,BLE_DURATION,SERIAL_DURATION,OUTPUT_ROOT,TARGET_IP,NETWORK_IFACE,SERIAL_DEVICES,INSTALL_DEPS,RUN_NMAP,RUN_BLE,RUN_SERIAL,RUN_PCAP bash "$0" "$@"
fi

if [[ "$INSTALL_DEPS" == "1" ]]; then
  missing=(); for c in tcpdump nmap bluetoothctl timeout ip node xxd strings; do have "$c" || missing+=("$c"); done
  if ((${#missing[@]})); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump nmap bluez iproute2 nodejs usbutils pciutils net-tools iw rfkill avahi-utils dnsutils socat python3 xxd binutils
  fi
fi

if [[ -z "$NETWORK_IFACE" ]]; then NETWORK_IFACE="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')"; fi
NETWORK_IFACE="${NETWORK_IFACE:-any}"

cat > "$OUT/manifest.env" <<EOF
capture_version=$VERSION
timestamp_utc=$STAMP
hostname=$HOSTNAME_SHORT
network_iface=$NETWORK_IFACE
target_ip=${TARGET_IP:-unset}
duration_seconds=$DURATION
EOF

uname -a > "$RAW/uname.txt" 2>&1 || true
cat /etc/os-release > "$RAW/os-release.txt" 2>&1 || true
ip -details address show > "$RAW/ip-address.txt" 2>&1 || true
ip route show table all > "$RAW/ip-routes.txt" 2>&1 || true
ip neigh show > "$RAW/ip-neighbors-before.txt" 2>&1 || true
ss -tunap > "$RAW/sockets-before.txt" 2>&1 || true
lsusb -v > "$RAW/lsusb.txt" 2>&1 || true
dmesg --ctime > "$RAW/dmesg-before.txt" 2>&1 || true
avahi-browse -art > "$RAW/avahi.txt" 2>&1 & PIDS+=("$!")

if [[ "$RUN_PCAP" == "1" ]]; then
  filter=(); [[ -n "$TARGET_IP" ]] && filter=(host "$TARGET_IP")
  timeout --signal=INT --kill-after=5 "$DURATION" tcpdump -i "$NETWORK_IFACE" -nn -s 0 -U -w "$RAW/network.pcap" "${filter[@]}" > "$RAW/tcpdump.txt" 2>&1 & PIDS+=("$!")
fi

if [[ "$RUN_NMAP" == "1" ]]; then
  cidr="$(ip -o -f inet addr show "$NETWORK_IFACE" 2>/dev/null | awk 'NR==1{print $4}')"
  [[ -n "$cidr" ]] && { nmap -sn "$cidr" -oA "$RAW/nmap-discovery" > "$RAW/nmap-discovery.log" 2>&1 & PIDS+=("$!"); }
  [[ -n "$TARGET_IP" ]] && { nmap -Pn -sT -sU --top-ports 200 -sV --version-light "$TARGET_IP" -oA "$RAW/nmap-target" > "$RAW/nmap-target.log" 2>&1 & PIDS+=("$!"); }
fi

if [[ "$RUN_BLE" == "1" ]] && have bluetoothctl; then
  bluetoothctl power on > "$RAW/bluetooth-power.txt" 2>&1 || true
  timeout --signal=INT --kill-after=3 "$BLE_DURATION" bluetoothctl --timeout "$BLE_DURATION" scan on > "$RAW/bluetooth-scan.txt" 2>&1 & PIDS+=("$!")
fi

serial_candidates(){
  if [[ "$SERIAL_DEVICES" != "auto" ]]; then tr ',' '\n' <<< "$SERIAL_DEVICES"; else find /dev/serial/by-id /dev -maxdepth 1 \( -name 'ttyUSB*' -o -name 'ttyACM*' -o -name 'serial0' -o -name 'ttyAMA*' \) -print 2>/dev/null | sort -u; fi
}

if [[ "$RUN_SERIAL" == "1" ]]; then
  mapfile -t devices < <(serial_candidates)
  printf '%s\n' "${devices[@]:-}" > "$RAW/serial-devices.txt"
  for dev in "${devices[@]:-}"; do
    [[ -c "$dev" ]] || continue
    safe="$(basename "$dev" | tr -cs 'A-Za-z0-9._-' '_')"; mkdir -p "$RAW/serial/$safe"
    stty -F "$dev" -g > "$RAW/serial/$safe/original-stty.txt" 2>&1 || true
    for baud in "${BAUD_RATES[@]}"; do
      dest="$RAW/serial/$safe/${baud}.bin"
      stty -F "$dev" "$baud" cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo 2> "$RAW/serial/$safe/${baud}.stty-error.txt" || continue
      timeout --signal=TERM --kill-after=2 "$SERIAL_DURATION" dd if="$dev" of="$dest" bs=4096 status=none 2> "$RAW/serial/$safe/${baud}.read-error.txt" || true
      xxd -g 1 -l 4096 "$dest" > "$RAW/serial/$safe/${baud}.hex.txt" 2>&1 || true
      strings -a -n 4 "$dest" > "$RAW/serial/$safe/${baud}.strings.txt" 2>&1 || true
    done
  done
fi

log "Capture running, power-cycle the RTK and exercise both link modes now"
sleep "$DURATION"
cleanup; trap - EXIT INT TERM
ip neigh show > "$RAW/ip-neighbors-after.txt" 2>&1 || true
ss -tunap > "$RAW/sockets-after.txt" 2>&1 || true
dmesg --ctime > "$RAW/dmesg-after.txt" 2>&1 || true
node "$(dirname "$0")/analyze.js" "$OUT" | tee "$OUT/summary.md"
(cd "$OUTPUT_ROOT" && tar -czf "$(basename "$OUT").tar.gz" "$(basename "$OUT")")
sha256sum "$OUTPUT_ROOT/$(basename "$OUT").tar.gz" > "$OUT/archive.sha256"
log "Capture complete: $OUT"

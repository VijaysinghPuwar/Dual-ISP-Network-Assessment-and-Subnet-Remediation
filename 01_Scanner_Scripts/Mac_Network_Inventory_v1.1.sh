#!/bin/bash
#
# Mac_Network_Inventory_v1.1.sh
#
# Authorized private-network inventory for macOS.
#
# Creates:
#   - Network_Inventory_Report.pdf
#   - Network_Inventory_Report.html
#   - Network_Devices.csv
#   - Network_Inventory.json
#   - Network_Inventory.txt
#   - Network_Inventory.log
#
# It scans RFC1918 private IPv4 networks only. It does not attempt passwords,
# exploit vulnerabilities, bypass firewalls, or change network settings.
#
# Version 1.1: parallel discovery, correct CIDR filtering, MAC collection,
# multicast exclusion, filtered ARP output, and macOS printf compatibility.
# Compatible with the Bash 3.2 version included with macOS.
#
# Examples:
#   chmod +x ./Mac_Network_Inventory_v1.1.sh
#   ./Mac_Network_Inventory_v1.1.sh --open-report
#
#   ./Mac_Network_Inventory_v1.1.sh \
#       --subnet 192.168.0.0/24 \
#       --subnet 192.168.1.0/24 \
#       --open-report
#
# Run this only on networks that you own or are authorized to assess.

set -u

VERSION="1.1"
PING_TIMEOUT_MS=500
TCP_TIMEOUT_SECONDS=1
MAX_HOSTS_PER_SUBNET=4096
PING_WORKERS=32
PORT_WORKERS=16
SKIP_PORT_SCAN=0
OPEN_REPORT=0
OUTPUT_DIRECTORY=""
WARNINGS_FILE=""
LOG_PATH=""
TEMP_DIRECTORY=""

PORTS=(
  22 23 53 80 135 139 443 445 515 548 631
  3389 5000 5001 5900 5985 5986 6690 8080 8443
  9100 32400
)

SUBNETS=()

usage() {
  cat <<'USAGE'
Mac Network Inventory v1.1

Usage:
  ./Mac_Network_Inventory_v1.1.sh [options]

Options:
  -s, --subnet CIDR          Private IPv4 subnet to scan. Repeat as needed.
                             Example: --subnet 192.168.0.0/24
  -o, --output DIRECTORY     Report output directory.
  --ping-timeout MS          Ping timeout in milliseconds. Default: 500
  --tcp-timeout SECONDS      TCP connect timeout. Default: 1
  --max-hosts NUMBER         Maximum hosts allowed per subnet. Default: 4096
  --skip-port-scan           Discover hosts without testing common TCP ports.
  --open-report              Open the PDF or HTML report when complete.
  -h, --help                 Show this help.

When no subnet is supplied, the script scans the private IPv4 subnet attached
to the Mac's current default network interface.
USAGE
}

timestamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

log_message() {
  level="$1"
  shift
  message="$*"
  line="[$(timestamp)] [$level] $message"
  printf '%s\n' "$line"
  if [ -n "${LOG_PATH:-}" ]; then
    printf '%s\n' "$line" >> "$LOG_PATH"
  fi
}

add_warning() {
  message="$*"
  log_message "WARN" "$message"
  if [ -n "${WARNINGS_FILE:-}" ]; then
    if ! grep -Fqx "$message" "$WARNINGS_FILE" 2>/dev/null; then
      printf '%s\n' "$message" >> "$WARNINGS_FILE"
    fi
  fi
}

cleanup() {
  if [ -n "${TEMP_DIRECTORY:-}" ] && [ -d "$TEMP_DIRECTORY" ]; then
    rm -rf "$TEMP_DIRECTORY"
  fi
}
trap cleanup EXIT INT TERM

sanitize_field() {
  printf '%s' "$1" | tr '\t\r\n|' '    '
}

html_escape() {
  printf '%s' "$1" |
    sed \
      -e 's/&/\&amp;/g' \
      -e 's/</\&lt;/g' \
      -e 's/>/\&gt;/g' \
      -e 's/"/\&quot;/g'
}

json_escape() {
  printf '%s' "$1" |
    sed \
      -e 's/\\/\\\\/g' \
      -e 's/"/\\"/g' \
      -e 's/	/\\t/g'
}

is_integer() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_ipv4() {
  local candidate_ip="$1"
  local old_ifs="$IFS"
  local octet

  IFS=.
  set -- $candidate_ip
  IFS="$old_ifs"

  [ "$#" -eq 4 ] || return 1

  for octet in "$@"; do
    is_integer "$octet" || return 1
    [ "$octet" -ge 0 ] 2>/dev/null || return 1
    [ "$octet" -le 255 ] 2>/dev/null || return 1
  done

  return 0
}

is_private_ipv4() {
  local candidate_ip="$1"
  local old_ifs="$IFS"
  local first second

  is_ipv4 "$candidate_ip" || return 1

  IFS=.
  set -- $candidate_ip
  IFS="$old_ifs"

  first="$1"
  second="$2"

  [ "$first" -eq 10 ] && return 0

  if [ "$first" -eq 172 ] && [ "$second" -ge 16 ] && [ "$second" -le 31 ]; then
    return 0
  fi

  if [ "$first" -eq 192 ] && [ "$second" -eq 168 ]; then
    return 0
  fi

  return 1
}

ip_to_int() {
  local candidate_ip="$1"
  local old_ifs="$IFS"

  IFS=.
  set -- $candidate_ip
  IFS="$old_ifs"

  echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 ))
}

int_to_ip() {
  local value="$1"
  echo "$(( (value >> 24) & 255 )).$(( (value >> 16) & 255 )).$(( (value >> 8) & 255 )).$(( value & 255 ))"
}

mask_to_prefix() {
  local mask="$1"
  local mask_value prefix bit

  case "$mask" in
    0x*|0X*)
      mask_value=$((mask))
      ;;
    *)
      if is_ipv4 "$mask"; then
        mask_value="$(ip_to_int "$mask")"
      else
        return 1
      fi
      ;;
  esac

  prefix=0
  bit=31
  while [ "$bit" -ge 0 ]; do
    if [ $(( (mask_value >> bit) & 1 )) -eq 1 ]; then
      prefix=$((prefix + 1))
    fi
    bit=$((bit - 1))
  done

  echo "$prefix"
}

# Sets global CIDR_* result variables without overwriting the caller's target IP.
parse_cidr() {
  local requested_cidr="$1"
  local cidr_ip prefix ip_int total host_mask all_bits mask
  local network broadcast first_host last_host host_count

  case "$requested_cidr" in
    */*)
      cidr_ip="${requested_cidr%/*}"
      prefix="${requested_cidr#*/}"
      ;;
    *)
      return 1
      ;;
  esac

  is_private_ipv4 "$cidr_ip" || return 1
  is_integer "$prefix" || return 1
  [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ] || return 1

  ip_int="$(ip_to_int "$cidr_ip")"
  total=$((1 << (32 - prefix)))
  host_mask=$((total - 1))
  all_bits=4294967295
  mask=$((all_bits - host_mask))
  network=$((ip_int & mask))
  broadcast=$((network + total - 1))

  if [ "$prefix" -eq 32 ]; then
    first_host="$network"
    last_host="$network"
    host_count=1
  elif [ "$prefix" -eq 31 ]; then
    first_host="$network"
    last_host="$broadcast"
    host_count=2
  else
    first_host=$((network + 1))
    last_host=$((broadcast - 1))
    host_count=$((total - 2))
  fi

  CIDR_PREFIX="$prefix"
  CIDR_NETWORK_INT="$network"
  CIDR_BROADCAST_INT="$broadcast"
  CIDR_FIRST_HOST_INT="$first_host"
  CIDR_LAST_HOST_INT="$last_host"
  CIDR_HOST_COUNT="$host_count"
  CIDR_NORMALIZED="$(int_to_ip "$network")/$prefix"

  return 0
}

ip_in_cidr() {
  local target_ip="$1"
  local target_cidr="$2"
  local value

  is_ipv4 "$target_ip" || return 1
  parse_cidr "$target_cidr" || return 1

  value="$(ip_to_int "$target_ip")"
  [ "$value" -ge "$CIDR_NETWORK_INT" ] &&
    [ "$value" -le "$CIDR_BROADCAST_INT" ]
}

ip_in_any_scanned_subnet() {
  local target_ip="$1"
  local subnet rest

  is_private_ipv4 "$target_ip" || return 1

  while IFS="$(printf '\t')" read -r subnet rest; do
    [ -n "$subnet" ] || continue
    if ip_in_cidr "$target_ip" "$subnet"; then
      return 0
    fi
  done < "$SUBNET_RESULTS_FILE"

  return 1
}

append_unique_line() {
  file="$1"
  value="$2"

  if ! grep -Fqx "$value" "$file" 2>/dev/null; then
    printf '%s\n' "$value" >> "$file"
  fi
}

service_name() {
  case "$1" in
    22) echo "SSH" ;;
    23) echo "Telnet" ;;
    53) echo "DNS" ;;
    80) echo "HTTP" ;;
    135) echo "MS RPC" ;;
    139) echo "NetBIOS" ;;
    443) echo "HTTPS" ;;
    445) echo "SMB" ;;
    515) echo "LPD Printing" ;;
    548) echo "AFP" ;;
    631) echo "IPP Printing" ;;
    3389) echo "RDP" ;;
    5000) echo "Web service / Synology DSM HTTP" ;;
    5001) echo "Synology DSM HTTPS" ;;
    5900) echo "VNC / Screen Sharing" ;;
    5985) echo "WinRM HTTP" ;;
    5986) echo "WinRM HTTPS" ;;
    6690) echo "Synology Drive" ;;
    8080) echo "Alternate HTTP" ;;
    8443) echo "Alternate HTTPS" ;;
    9100) echo "JetDirect Printing" ;;
    32400) echo "Plex" ;;
    *) echo "TCP" ;;
  esac
}

contains_port() {
  csv="$1"
  port="$2"

  case ",$csv," in
    *",$port,"*) return 0 ;;
    *) return 1 ;;
  esac
}

classify_device() {
  ip="$1"
  ports_csv="$2"
  is_gateway="$3"
  is_local="$4"
  host_name="$5"

  if [ "$is_local" = "true" ]; then
    echo "This Mac"
    return
  fi

  if [ "$is_gateway" = "true" ]; then
    echo "Router / default gateway"
    return
  fi

  if contains_port "$ports_csv" 5000 ||
     contains_port "$ports_csv" 5001 ||
     contains_port "$ports_csv" 6690; then
    echo "Synology NAS or DSM web device (likely)"
    return
  fi

  if contains_port "$ports_csv" 3389 ||
     contains_port "$ports_csv" 5985 ||
     contains_port "$ports_csv" 5986 ||
     contains_port "$ports_csv" 135; then
    echo "Windows PC or server (likely)"
    return
  fi

  if contains_port "$ports_csv" 548 ||
     contains_port "$ports_csv" 5900; then
    echo "Mac or Apple device (likely)"
    return
  fi

  if contains_port "$ports_csv" 9100 ||
     contains_port "$ports_csv" 515 ||
     contains_port "$ports_csv" 631; then
    echo "Network printer (likely)"
    return
  fi

  if contains_port "$ports_csv" 53 &&
     { contains_port "$ports_csv" 80 || contains_port "$ports_csv" 443; }; then
    echo "Router or network appliance (likely)"
    return
  fi

  case "$host_name" in
    *[Ss]ynology*|*[Dd]isk[Ss]tation*|*[Rr]ack[Ss]tation*)
      echo "Synology NAS (hostname indication)"
      return
      ;;
    *[Mm]ac[Bb]ook*|*[Ii][Mm]ac*|*[Mm]ac-[Mm]ini*|*[Aa]pple*)
      echo "Mac or Apple device (hostname indication)"
      return
      ;;
  esac

  if [ -n "$ports_csv" ]; then
    echo "Network host with TCP services"
  else
    echo "Unknown network device"
  fi
}

resolve_hostname() {
  ip="$1"
  name=""

  if command -v dscacheutil >/dev/null 2>&1; then
    name="$(dscacheutil -q host -a ip_address "$ip" 2>/dev/null |
      awk -F': ' '/^name:/{print $2; exit}')"
  fi

  if [ -z "$name" ] && command -v host >/dev/null 2>&1; then
    name="$(host "$ip" 2>/dev/null |
      awk '/domain name pointer/{print $NF; exit}' |
      sed 's/\.$//')"
  fi

  printf '%s' "$name"
}

get_arp_mac() {
  local target_ip="$1"

  awk -v target="($target_ip)" '
    $2 == target && $3 == "at" && $4 != "(incomplete)" {
      print toupper($4)
      exit
    }
  ' "$ARP_FILE"
}

probe_tcp_ports() {
  local target_ip="$1"
  local result=""
  local probe_dir batch_count port result_file

  if [ "$SKIP_PORT_SCAN" -eq 1 ]; then
    printf ''
    return
  fi

  probe_dir="$TEMP_DIRECTORY/ports_$(printf '%s' "$target_ip" | tr '.' '_')"
  rm -rf "$probe_dir"
  mkdir -p "$probe_dir"
  batch_count=0

  for port in "${PORTS[@]}"; do
    (
      if nc -z -G "$TCP_TIMEOUT_SECONDS" -w "$TCP_TIMEOUT_SECONDS" \
        "$target_ip" "$port" >/dev/null 2>&1; then
        printf '%s\n' "$port" > "$probe_dir/$port.open"
      fi
    ) &

    batch_count=$((batch_count + 1))
    if [ "$batch_count" -ge "$PORT_WORKERS" ]; then
      wait
      batch_count=0
    fi
  done
  wait

  result="$(
    for result_file in "$probe_dir"/*.open; do
      [ -e "$result_file" ] || continue
      basename "$result_file" .open
    done | sort -n | paste -sd, -
  )"

  printf '%s' "$result"
}

ports_to_services() {
  ports_csv="$1"
  services=""

  [ -n "$ports_csv" ] || {
    printf ''
    return
  }

  old_ifs="$IFS"
  IFS=,
  set -- $ports_csv
  IFS="$old_ifs"

  for port in "$@"; do
    label="$(service_name "$port")"
    entry="$port/$label"

    if [ -n "$services" ]; then
      services="$services; $entry"
    else
      services="$entry"
    fi
  done

  printf '%s' "$services"
}

detect_default_network() {
  DEFAULT_INTERFACE="$(route -n get default 2>/dev/null |
    awk '/interface:/{print $2; exit}')"
  DEFAULT_GATEWAY="$(route -n get default 2>/dev/null |
    awk '/gateway:/{print $2; exit}')"

  if [ -z "$DEFAULT_INTERFACE" ]; then
    return 1
  fi

  DEFAULT_IP="$(ipconfig getifaddr "$DEFAULT_INTERFACE" 2>/dev/null)"

  if [ -z "$DEFAULT_IP" ]; then
    DEFAULT_IP="$(ifconfig "$DEFAULT_INTERFACE" 2>/dev/null |
      awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')"
  fi

  mask="$(ifconfig "$DEFAULT_INTERFACE" 2>/dev/null |
    awk '/inet / && $2 != "127.0.0.1" {print $4; exit}')"

  if [ -z "$DEFAULT_IP" ] || [ -z "$mask" ]; then
    return 1
  fi

  prefix="$(mask_to_prefix "$mask")" || return 1
  parse_cidr "$DEFAULT_IP/$prefix" || return 1
  DEFAULT_SUBNET="$CIDR_NORMALIZED"

  return 0
}

collect_adapters() {
  : > "$ADAPTERS_FILE"

  if ! command -v networksetup >/dev/null 2>&1; then
    return
  fi

  networksetup -listallhardwareports 2>/dev/null |
    awk '
      /^Hardware Port:/ {
        if (device != "") {
          print hardware "\t" device "\t" mac
        }
        hardware = substr($0, index($0, ":") + 2)
        device = ""
        mac = ""
      }
      /^Device:/ {
        device = substr($0, index($0, ":") + 2)
      }
      /^Ethernet Address:/ {
        mac = substr($0, index($0, ":") + 2)
      }
      END {
        if (device != "") {
          print hardware "\t" device "\t" mac
        }
      }
    ' |
    while IFS="$(printf '\t')" read -r hardware device mac; do
      [ -n "$device" ] || continue

      ipv4="$(ipconfig getifaddr "$device" 2>/dev/null)"
      status="$(ifconfig "$device" 2>/dev/null |
        awk -F': ' '/status:/{print $2; exit}')"
      media="$(ifconfig "$device" 2>/dev/null |
        awk -F': ' '/media:/{print $2; exit}')"

      if [ "$device" = "$DEFAULT_INTERFACE" ]; then
        gateway="$DEFAULT_GATEWAY"
        dns="$DNS_SERVERS"
      else
        gateway=""
        dns=""
      fi

      printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$(sanitize_field "$hardware")" \
        "$(sanitize_field "$device")" \
        "$(sanitize_field "$status")" \
        "$(sanitize_field "$media")" \
        "$(sanitize_field "$mac")" \
        "$(sanitize_field "$ipv4")" \
        "$(sanitize_field "$gateway")" \
        "$(sanitize_field "$dns")" \
        >> "$ADAPTERS_FILE"
    done
}

write_devices_csv() {
  {
    printf '"IPAddress","HostName","MacAddress","Interface","Reachability","PingMs","IsDefaultGateway","LikelyDevice","OpenTcpServices","Notes"\n'

    while IFS='|' read -r ip hostname mac interface reachability ping_ms is_gateway likely services notes; do
      printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
        "$(printf '%s' "$ip" | sed 's/"/""/g')" \
        "$(printf '%s' "$hostname" | sed 's/"/""/g')" \
        "$(printf '%s' "$mac" | sed 's/"/""/g')" \
        "$(printf '%s' "$interface" | sed 's/"/""/g')" \
        "$(printf '%s' "$reachability" | sed 's/"/""/g')" \
        "$(printf '%s' "$ping_ms" | sed 's/"/""/g')" \
        "$(printf '%s' "$is_gateway" | sed 's/"/""/g')" \
        "$(printf '%s' "$likely" | sed 's/"/""/g')" \
        "$(printf '%s' "$services" | sed 's/"/""/g')" \
        "$(printf '%s' "$notes" | sed 's/"/""/g')"
    done < "$DEVICES_FILE"
  } > "$CSV_PATH"
}

write_json_report() {
  {
    printf '{\n'
    printf '  "Summary": {\n'
    printf '    "ReportGenerated": "%s",\n' "$(json_escape "$COMPLETED_AT")"
    printf '    "DurationSeconds": %s,\n' "$DURATION_SECONDS"
    printf '    "SubnetsScanned": %s,\n' "$SCANNED_SUBNET_COUNT"
    printf '    "AddressesTested": %s,\n' "$ADDRESSES_TESTED"
    printf '    "DevicesDiscovered": %s,\n' "$DEVICE_COUNT"
    printf '    "DefaultGateway": "%s",\n' "$(json_escape "$DEFAULT_GATEWAY")"
    printf '    "OpenTcpServicesFound": %s,\n' "$OPEN_SERVICE_COUNT"
    if [ "$SKIP_PORT_SCAN" -eq 1 ]; then
      printf '    "PortScanEnabled": false\n'
    else
      printf '    "PortScanEnabled": true\n'
    fi
    printf '  },\n'

    printf '  "LocalSystem": {\n'
    printf '    "ComputerName": "%s",\n' "$(json_escape "$COMPUTER_NAME")"
    printf '    "CurrentUser": "%s",\n' "$(json_escape "$CURRENT_USER")"
    printf '    "ModelName": "%s",\n' "$(json_escape "$MODEL_NAME")"
    printf '    "ModelIdentifier": "%s",\n' "$(json_escape "$MODEL_IDENTIFIER")"
    printf '    "Chip": "%s",\n' "$(json_escape "$CHIP_NAME")"
    printf '    "Memory": "%s",\n' "$(json_escape "$MEMORY")"
    printf '    "OperatingSystem": "%s",\n' "$(json_escape "$OPERATING_SYSTEM")"
    printf '    "DefaultInterface": "%s",\n' "$(json_escape "$DEFAULT_INTERFACE")"
    printf '    "IPv4Address": "%s"\n' "$(json_escape "$DEFAULT_IP")"
    printf '  },\n'

    printf '  "NetworkAdapters": [\n'
    first=1
    while IFS='|' read -r hardware device status media mac ipv4 gateway dns; do
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    {"HardwarePort":"%s","Device":"%s","Status":"%s","Media":"%s","MacAddress":"%s","IPv4":"%s","DefaultGateway":"%s","DnsServers":"%s"}' \
        "$(json_escape "$hardware")" \
        "$(json_escape "$device")" \
        "$(json_escape "$status")" \
        "$(json_escape "$media")" \
        "$(json_escape "$mac")" \
        "$(json_escape "$ipv4")" \
        "$(json_escape "$gateway")" \
        "$(json_escape "$dns")"
    done < "$ADAPTERS_FILE"
    printf '\n  ],\n'

    printf '  "SubnetResults": [\n'
    first=1
    while IFS="$(printf '\t')" read -r subnet prefix network broadcast host_count tested responsive status; do
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    {"Subnet":"%s","PrefixLength":%s,"Network":"%s","Broadcast":"%s","HostCapacity":%s,"AddressesTested":%s,"PingResponsive":%s,"Status":"%s"}' \
        "$(json_escape "$subnet")" \
        "$prefix" \
        "$(json_escape "$network")" \
        "$(json_escape "$broadcast")" \
        "$host_count" \
        "$tested" \
        "$responsive" \
        "$(json_escape "$status")"
    done < "$SUBNET_RESULTS_FILE"
    printf '\n  ],\n'

    printf '  "Devices": [\n'
    first=1
    while IFS='|' read -r ip hostname mac interface reachability ping_ms is_gateway likely services notes; do
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    {"IPAddress":"%s","HostName":"%s","MacAddress":"%s","Interface":"%s","Reachability":"%s","PingMs":"%s","IsDefaultGateway":%s,"LikelyDevice":"%s","OpenTcpServices":"%s","Notes":"%s"}' \
        "$(json_escape "$ip")" \
        "$(json_escape "$hostname")" \
        "$(json_escape "$mac")" \
        "$(json_escape "$interface")" \
        "$(json_escape "$reachability")" \
        "$(json_escape "$ping_ms")" \
        "$is_gateway" \
        "$(json_escape "$likely")" \
        "$(json_escape "$services")" \
        "$(json_escape "$notes")"
    done < "$DEVICES_FILE"
    printf '\n  ],\n'

    printf '  "Warnings": [\n'
    first=1
    while IFS= read -r warning; do
      [ -n "$warning" ] || continue
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    "%s"' "$(json_escape "$warning")"
    done < "$WARNINGS_FILE"
    printf '\n  ]\n'
    printf '}\n'
  } > "$JSON_PATH"
}

write_text_report() {
  {
    printf 'MAC PRIVATE NETWORK INVENTORY\n'
    printf '=============================\n\n'
    printf 'Generated: %s\n' "$COMPLETED_AT"
    printf 'Computer: %s\n' "$COMPUTER_NAME"
    printf 'User: %s\n\n' "$CURRENT_USER"

    printf 'EXECUTIVE SUMMARY\n'
    printf '%s\n' '-----------------'
    printf 'Subnets scanned: %s\n' "$SCANNED_SUBNET_COUNT"
    printf 'Addresses tested: %s\n' "$ADDRESSES_TESTED"
    printf 'Devices discovered: %s\n' "$DEVICE_COUNT"
    printf 'Default gateway: %s\n' "$DEFAULT_GATEWAY"
    printf 'Open TCP services found: %s\n' "$OPEN_SERVICE_COUNT"
    printf 'Duration: %s seconds\n\n' "$DURATION_SECONDS"

    printf 'DISCOVERED DEVICES\n'
    printf '%s\n' '------------------'
    while IFS='|' read -r ip hostname mac interface reachability ping_ms is_gateway likely services notes; do
      printf 'IP: %s\n' "$ip"
      printf '  Likely device: %s\n' "$likely"
      printf '  Hostname: %s\n' "${hostname:-Not resolved}"
      printf '  MAC: %s\n' "${mac:-Not available}"
      printf '  Reachability: %s\n' "$reachability"
      printf '  Ping: %s ms\n' "${ping_ms:-Not available}"
      printf '  Default gateway: %s\n' "$is_gateway"
      printf '  Services: %s\n' "${services:-No tested TCP ports open}"
      printf '  Notes: %s\n\n' "${notes:-None}"
    done < "$DEVICES_FILE"

    printf 'LOCAL MAC\n'
    printf '%s\n' '---------'
    printf 'Model: %s\n' "$MODEL_NAME"
    printf 'Model identifier: %s\n' "$MODEL_IDENTIFIER"
    printf 'Chip: %s\n' "$CHIP_NAME"
    printf 'Memory: %s\n' "$MEMORY"
    printf 'Operating system: %s\n' "$OPERATING_SYSTEM"
    printf 'Default interface: %s\n' "$DEFAULT_INTERFACE"
    printf 'IPv4: %s\n' "$DEFAULT_IP"
    printf 'Gateway: %s\n' "$DEFAULT_GATEWAY"
    printf 'DNS: %s\n\n' "$DNS_SERVERS"

    printf 'NETWORK ADAPTERS\n'
    printf '%s\n' '----------------'
    while IFS='|' read -r hardware device status media mac ipv4 gateway dns; do
      printf '%s (%s)\n' "$hardware" "$device"
      printf '  Status: %s\n' "${status:-Unknown}"
      printf '  Media: %s\n' "${media:-Unknown}"
      printf '  MAC: %s\n' "${mac:-Unknown}"
      printf '  IPv4: %s\n' "${ipv4:-None}"
      printf '  Gateway: %s\n' "${gateway:-None}"
      printf '  DNS: %s\n\n' "${dns:-None}"
    done < "$ADAPTERS_FILE"

    printf 'IPv4 ROUTING TABLE\n'
    printf '%s\n' '------------------'
    cat "$ROUTES_FILE"
    printf '\n\nARP / NEIGHBOR CACHE\n'
    printf '%s\n' '--------------------'
    cat "$ARP_FILE"
    printf '\n\nWARNINGS AND LIMITATIONS\n'
    printf '%s\n' '------------------------'
    while IFS= read -r warning; do
      [ -n "$warning" ] && printf '%s\n' "- $warning"
    done < "$WARNINGS_FILE"
  } > "$TEXT_PATH"
}

write_html_report() {
  {
    cat <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Mac Private Network Inventory</title>
<style>
@page { size: A4 landscape; margin: 10mm; }
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #f3f6fa;
  color: #172033;
  font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
  font-size: 10.5px;
}
.container { max-width: 1500px; margin: 0 auto; padding: 24px; }
.header {
  background: linear-gradient(135deg, #152a45, #315f83);
  color: white;
  border-radius: 12px;
  padding: 24px 28px;
  margin-bottom: 18px;
}
.header h1 { margin: 0 0 7px; font-size: 28px; }
.header p { margin: 4px 0; opacity: .93; }
.badge {
  display: inline-block;
  margin-top: 10px;
  padding: 5px 9px;
  border: 1px solid rgba(255,255,255,.45);
  border-radius: 999px;
  font-size: 9px;
}
.cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin-bottom: 18px;
}
.card, .section {
  background: white;
  border: 1px solid #dbe3ed;
  border-radius: 10px;
}
.card { padding: 13px 15px; }
.card span {
  display: block;
  color: #526177;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: .06em;
}
.card strong { display: block; margin-top: 4px; font-size: 21px; }
.section { padding: 16px; margin-bottom: 14px; }
.section h2 {
  margin: 0 0 10px;
  padding-bottom: 7px;
  border-bottom: 2px solid #e8eef5;
  color: #173f63;
  font-size: 17px;
}
table { width: 100%; border-collapse: collapse; }
th, td {
  border: 1px solid #d8e0ea;
  padding: 6px 7px;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th { background: #eaf1f8; color: #173f63; }
tr:nth-child(even) td { background: #f8fafc; }
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-family: Menlo, Monaco, monospace;
  font-size: 9px;
}
.warning { border-left: 5px solid #bf7a00; background: #fff8e8; }
.muted { color: #6c7889; font-style: italic; }
.footer { color: #657287; text-align: center; font-size: 9px; padding: 8px; }
</style>
</head>
<body>
<div class="container">
HTML_HEAD

    printf '<div class="header">\n'
    printf '<h1>Mac Private Network Inventory</h1>\n'
    printf '<p>Computer: %s</p>\n' "$(html_escape "$COMPUTER_NAME")"
    printf '<p>Generated: %s</p>\n' "$(html_escape "$COMPLETED_AT")"
    printf '<p>Perspective: %s - %s</p>\n' \
      "$(html_escape "$DEFAULT_INTERFACE")" \
      "$(html_escape "$DEFAULT_IP")"
    printf '<div class="badge">Authorized RFC1918 inventory: no credential attacks or vulnerability exploitation</div>\n'
    printf '</div>\n'

    printf '<div class="cards">\n'
    printf '<div class="card"><span>Devices</span><strong>%s</strong></div>\n' "$DEVICE_COUNT"
    printf '<div class="card"><span>Addresses tested</span><strong>%s</strong></div>\n' "$ADDRESSES_TESTED"
    printf '<div class="card"><span>Subnets scanned</span><strong>%s</strong></div>\n' "$SCANNED_SUBNET_COUNT"
    printf '<div class="card"><span>Open TCP services</span><strong>%s</strong></div>\n' "$OPEN_SERVICE_COUNT"
    printf '</div>\n'

    printf '<div class="section"><h2>Executive Summary</h2><table>\n'
    printf '<tr><th>Duration</th><th>Default interface</th><th>Mac IPv4</th><th>Default gateway</th><th>DNS</th><th>Port scan enabled</th></tr>\n'
    printf '<tr><td>%s seconds</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
      "$DURATION_SECONDS" \
      "$(html_escape "$DEFAULT_INTERFACE")" \
      "$(html_escape "$DEFAULT_IP")" \
      "$(html_escape "$DEFAULT_GATEWAY")" \
      "$(html_escape "$DNS_SERVERS")" \
      "$([ "$SKIP_PORT_SCAN" -eq 1 ] && echo "False" || echo "True")"
    printf '</table></div>\n'

    printf '<div class="section"><h2>Discovered Device Inventory</h2><table>\n'
    printf '<tr><th>IP address</th><th>Hostname</th><th>MAC address</th><th>Interface</th><th>Reachability</th><th>Ping</th><th>Gateway</th><th>Likely device</th><th>Open TCP services</th><th>Notes</th></tr>\n'
    while IFS='|' read -r ip hostname mac interface reachability ping_ms is_gateway likely services notes; do
      printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$ip")" \
        "$(html_escape "$hostname")" \
        "$(html_escape "$mac")" \
        "$(html_escape "$interface")" \
        "$(html_escape "$reachability")" \
        "$(html_escape "$ping_ms")" \
        "$(html_escape "$is_gateway")" \
        "$(html_escape "$likely")" \
        "$(html_escape "$services")" \
        "$(html_escape "$notes")"
    done < "$DEVICES_FILE"
    printf '</table></div>\n'

    printf '<div class="section"><h2>Subnet Scan Results</h2><table>\n'
    printf '<tr><th>Subnet</th><th>Network</th><th>Broadcast</th><th>Host capacity</th><th>Addresses tested</th><th>Ping responsive</th><th>Status</th></tr>\n'
    while IFS="$(printf '\t')" read -r subnet prefix network broadcast host_count tested responsive status; do
      printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$subnet")" \
        "$(html_escape "$network")" \
        "$(html_escape "$broadcast")" \
        "$host_count" "$tested" "$responsive" "$(html_escape "$status")"
    done < "$SUBNET_RESULTS_FILE"
    printf '</table></div>\n'

    printf '<div class="section"><h2>Local Mac</h2><table>\n'
    printf '<tr><th>Computer</th><th>User</th><th>Model</th><th>Identifier</th><th>Chip</th><th>Memory</th><th>Operating system</th></tr>\n'
    printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
      "$(html_escape "$COMPUTER_NAME")" \
      "$(html_escape "$CURRENT_USER")" \
      "$(html_escape "$MODEL_NAME")" \
      "$(html_escape "$MODEL_IDENTIFIER")" \
      "$(html_escape "$CHIP_NAME")" \
      "$(html_escape "$MEMORY")" \
      "$(html_escape "$OPERATING_SYSTEM")"
    printf '</table></div>\n'

    printf '<div class="section"><h2>Network Adapters</h2><table>\n'
    printf '<tr><th>Hardware port</th><th>Device</th><th>Status</th><th>Media</th><th>MAC address</th><th>IPv4</th><th>Gateway</th><th>DNS</th></tr>\n'
    while IFS='|' read -r hardware device status media mac ipv4 gateway dns; do
      printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$hardware")" \
        "$(html_escape "$device")" \
        "$(html_escape "$status")" \
        "$(html_escape "$media")" \
        "$(html_escape "$mac")" \
        "$(html_escape "$ipv4")" \
        "$(html_escape "$gateway")" \
        "$(html_escape "$dns")"
    done < "$ADAPTERS_FILE"
    printf '</table></div>\n'

    printf '<div class="section"><h2>IPv4 Routing Table</h2><pre>%s</pre></div>\n' \
      "$(html_escape "$(cat "$ROUTES_FILE")")"

    printf '<div class="section"><h2>ARP / Neighbor Cache</h2><pre>%s</pre></div>\n' \
      "$(html_escape "$(cat "$ARP_FILE")")"

    printf '<div class="section warning"><h2>Interpretation and Limitations</h2><ul>\n'
    while IFS= read -r warning; do
      [ -n "$warning" ] && printf '<li>%s</li>\n' "$(html_escape "$warning")"
    done < "$WARNINGS_FILE"
    printf '</ul></div>\n'

    printf '<div class="footer">Files in this report package: PDF, HTML, CSV device inventory, JSON data, text report, and scan log.</div>\n'
    printf '</div></body></html>\n'
  } > "$HTML_PATH"
}

convert_report_to_pdf() {
  browser=""

  for candidate in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "$HOME/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"; do

    if [ -x "$candidate" ]; then
      browser="$candidate"
      break
    fi
  done

  if [ -n "$browser" ]; then
    log_message "INFO" "Creating PDF with $(basename "$browser")."

    "$browser" \
      --headless \
      --disable-gpu \
      --user-data-dir="$TEMP_DIRECTORY/browser-profile" \
      --no-pdf-header-footer \
      --print-to-pdf="$PDF_PATH" \
      "file://$HTML_PATH" \
      >/dev/null 2>&1

    if [ -s "$PDF_PATH" ]; then
      log_message "OK" "PDF report created with $(basename "$browser"): $PDF_PATH"
      return 0
    fi
  fi

  if command -v cupsfilter >/dev/null 2>&1; then
    log_message "INFO" "Creating PDF with macOS cupsfilter fallback."

    cupsfilter -m application/pdf "$TEXT_PATH" > "$PDF_PATH" 2>/dev/null

    if [ -s "$PDF_PATH" ]; then
      log_message "OK" "PDF report created with cupsfilter: $PDF_PATH"
      return 0
    fi
  fi

  add_warning "Automatic PDF conversion was unavailable. The complete HTML and text reports were still created."
  return 1
}

# Parse command-line options.
while [ "$#" -gt 0 ]; do
  case "$1" in
    -s|--subnet)
      [ "$#" -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 2
      }
      SUBNETS[${#SUBNETS[@]}]="$2"
      shift 2
      ;;
    -o|--output)
      [ "$#" -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 2
      }
      OUTPUT_DIRECTORY="$2"
      shift 2
      ;;
    --ping-timeout)
      [ "$#" -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 2
      }
      PING_TIMEOUT_MS="$2"
      shift 2
      ;;
    --tcp-timeout)
      [ "$#" -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 2
      }
      TCP_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --max-hosts)
      [ "$#" -ge 2 ] || {
        echo "Missing value for $1" >&2
        exit 2
      }
      MAX_HOSTS_PER_SUBNET="$2"
      shift 2
      ;;
    --skip-port-scan)
      SKIP_PORT_SCAN=1
      shift
      ;;
    --open-report)
      OPEN_REPORT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for numeric_value in "$PING_TIMEOUT_MS" "$TCP_TIMEOUT_SECONDS" "$MAX_HOSTS_PER_SUBNET"; do
  is_integer "$numeric_value" || {
    echo "Timeout and host-limit values must be positive integers." >&2
    exit 2
  }
done

[ "$PING_TIMEOUT_MS" -ge 100 ] || {
  echo "Ping timeout must be at least 100 milliseconds." >&2
  exit 2
}

[ "$TCP_TIMEOUT_SECONDS" -ge 1 ] || {
  echo "TCP timeout must be at least 1 second." >&2
  exit 2
}

[ "$MAX_HOSTS_PER_SUBNET" -ge 1 ] || {
  echo "Maximum hosts must be at least 1." >&2
  exit 2
}

START_EPOCH="$(date +%s)"
STARTED_AT="$(date "+%Y-%m-%d %H:%M:%S %z")"

if [ -z "$OUTPUT_DIRECTORY" ]; then
  OUTPUT_DIRECTORY="$HOME/Desktop/Mac_Network_Inventory_$(date "+%Y%m%d_%H%M%S")"
fi

mkdir -p "$OUTPUT_DIRECTORY" || {
  echo "Unable to create output directory: $OUTPUT_DIRECTORY" >&2
  exit 1
}

# Resolve to an absolute path.
OUTPUT_DIRECTORY="$(cd "$OUTPUT_DIRECTORY" && pwd)"

LOG_PATH="$OUTPUT_DIRECTORY/Network_Inventory.log"
HTML_PATH="$OUTPUT_DIRECTORY/Network_Inventory_Report.html"
PDF_PATH="$OUTPUT_DIRECTORY/Network_Inventory_Report.pdf"
CSV_PATH="$OUTPUT_DIRECTORY/Network_Devices.csv"
JSON_PATH="$OUTPUT_DIRECTORY/Network_Inventory.json"
TEXT_PATH="$OUTPUT_DIRECTORY/Network_Inventory.txt"

TEMP_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/mac_network_inventory.XXXXXX")" || exit 1
WARNINGS_FILE="$TEMP_DIRECTORY/warnings.txt"
ALIVE_FILE="$TEMP_DIRECTORY/alive.tsv"
DISCOVERED_FILE="$TEMP_DIRECTORY/discovered_ips.txt"
SUBNET_RESULTS_FILE="$TEMP_DIRECTORY/subnet_results.tsv"
DEVICES_FILE="$TEMP_DIRECTORY/devices.tsv"
ADAPTERS_FILE="$TEMP_DIRECTORY/adapters.tsv"
ROUTES_FILE="$TEMP_DIRECTORY/routes.txt"
ARP_FILE="$TEMP_DIRECTORY/arp.txt"
ARP_RAW_FILE="$TEMP_DIRECTORY/arp_raw.txt"

: > "$LOG_PATH"
: > "$WARNINGS_FILE"
: > "$ALIVE_FILE"
: > "$DISCOVERED_FILE"
: > "$SUBNET_RESULTS_FILE"
: > "$DEVICES_FILE"
: > "$ADAPTERS_FILE"
: > "$ROUTES_FILE"
: > "$ARP_FILE"
: > "$ARP_RAW_FILE"

log_message "INFO" "Mac Network Inventory v$VERSION: authorized private-network inventory started at $STARTED_AT."
log_message "INFO" "Output directory: $OUTPUT_DIRECTORY"

if ! detect_default_network; then
  log_message "ERROR" "Unable to detect the Mac's default private IPv4 network."
  log_message "ERROR" "Supply a subnet manually, for example: --subnet 192.168.0.0/24"
  exit 1
fi

if ! is_private_ipv4 "$DEFAULT_IP"; then
  log_message "ERROR" "Default interface IPv4 address is not an RFC1918 private address: $DEFAULT_IP"
  exit 1
fi

if [ "${#SUBNETS[@]}" -eq 0 ]; then
  SUBNETS[0]="$DEFAULT_SUBNET"
  log_message "INFO" "Auto-detected subnet: $DEFAULT_SUBNET"
else
  log_message "INFO" "Using user-specified subnet(s): ${SUBNETS[*]}"
fi

DEFAULT_MAC="$(ifconfig "$DEFAULT_INTERFACE" 2>/dev/null | awk '/ether /{print toupper($2); exit}')"

DNS_SERVERS="$(scutil --dns 2>/dev/null |
  awk '/nameserver\[[0-9]+\]/{print $3}' |
  sort -u |
  paste -sd, -)"

COMPUTER_NAME="$(scutil --get ComputerName 2>/dev/null)"
[ -n "$COMPUTER_NAME" ] || COMPUTER_NAME="$(hostname)"
CURRENT_USER="$(id -un)"

MODEL_NAME="$(system_profiler SPHardwareDataType 2>/dev/null |
  awk -F': ' '/Model Name:/{print $2; exit}')"
MODEL_IDENTIFIER="$(system_profiler SPHardwareDataType 2>/dev/null |
  awk -F': ' '/Model Identifier:/{print $2; exit}')"
CHIP_NAME="$(system_profiler SPHardwareDataType 2>/dev/null |
  awk -F': ' '/Chip:|Processor Name:/{print $2; exit}')"
MEMORY="$(system_profiler SPHardwareDataType 2>/dev/null |
  awk -F': ' '/Memory:/{print $2; exit}')"
OPERATING_SYSTEM="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) (Build $(sw_vers -buildVersion 2>/dev/null))"

collect_adapters
netstat -rn -f inet > "$ROUTES_FILE" 2>&1
arp -an > "$ARP_RAW_FILE" 2>&1

ADDRESSES_TESTED=0
SCANNED_SUBNET_COUNT=0

# Scan each requested subnet.
for requested_cidr in "${SUBNETS[@]}"; do
  if ! parse_cidr "$requested_cidr"; then
    add_warning "Skipped invalid or non-private subnet: $requested_cidr"
    continue
  fi

  subnet="$CIDR_NORMALIZED"
  prefix="$CIDR_PREFIX"
  network_ip="$(int_to_ip "$CIDR_NETWORK_INT")"
  broadcast_ip="$(int_to_ip "$CIDR_BROADCAST_INT")"
  host_count="$CIDR_HOST_COUNT"

  if [ "$host_count" -gt "$MAX_HOSTS_PER_SUBNET" ]; then
    add_warning "Skipped $subnet because it contains $host_count hosts, exceeding --max-hosts $MAX_HOSTS_PER_SUBNET."
    printf '%s\t%s\t%s\t%s\t%s\t0\t0\t%s\n' \
      "$subnet" "$prefix" "$network_ip" "$broadcast_ip" "$host_count" \
      "Skipped - too large" >> "$SUBNET_RESULTS_FILE"
    continue
  fi

  log_message "INFO" "Scanning subnet $subnet ($host_count possible hosts)."

  tested=0
  responsive=0
  current="$CIDR_FIRST_HOST_INT"
  ping_batch_count=0
  ping_dir="$TEMP_DIRECTORY/ping_$(printf '%s' "$network_ip" | tr '.' '_')_$prefix"
  rm -rf "$ping_dir"
  mkdir -p "$ping_dir"

  while [ "$current" -le "$CIDR_LAST_HOST_INT" ]; do
    ip="$(int_to_ip "$current")"
    tested=$((tested + 1))
    ADDRESSES_TESTED=$((ADDRESSES_TESTED + 1))

    printf '\rLaunching ping probes for %-18s host %4s of %4s' \
      "$subnet" "$tested" "$host_count"

    (
      ping_output="$(ping -n -c 1 -W "$PING_TIMEOUT_MS" "$ip" 2>/dev/null)"
      if [ "$?" -eq 0 ]; then
        ping_ms="$(printf '%s\n' "$ping_output" |
          sed -n 's/.*time[=<]\([0-9.]*\) ms.*/\1/p' |
          head -n 1)"
        [ -n "$ping_ms" ] || ping_ms="0"
        printf '%s\t%s\n' "$ip" "$ping_ms" > "$ping_dir/$current.result"
      fi
    ) &

    ping_batch_count=$((ping_batch_count + 1))
    if [ "$ping_batch_count" -ge "$PING_WORKERS" ]; then
      wait
      ping_batch_count=0
    fi

    current=$((current + 1))
  done
  wait
  printf '\n'

  for ping_result_file in "$ping_dir"/*.result; do
    [ -e "$ping_result_file" ] || continue
    cat "$ping_result_file" >> "$ALIVE_FILE"
    discovered_ip="$(awk -F'\t' '{print $1; exit}' "$ping_result_file")"
    append_unique_line "$DISCOVERED_FILE" "$discovered_ip"
    responsive=$((responsive + 1))
  done

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$subnet" "$prefix" "$network_ip" "$broadcast_ip" "$host_count" \
    "$tested" "$responsive" "Scanned" >> "$SUBNET_RESULTS_FILE"

  SCANNED_SUBNET_COUNT=$((SCANNED_SUBNET_COUNT + 1))
done

if [ "$SCANNED_SUBNET_COUNT" -eq 0 ]; then
  log_message "ERROR" "No subnet was scanned successfully."
  exit 1
fi

# Refresh ARP after discovery. Keep only complete, private entries from
# the scanned subnet(s); multicast entries are not physical devices.
arp -an > "$ARP_RAW_FILE" 2>&1
: > "$ARP_FILE"

while IFS= read -r arp_line; do
  arp_ip="$(printf '%s\n' "$arp_line" |
    sed -n 's/.*(\([0-9][0-9.]*\)).*/\1/p')"

  [ -n "$arp_ip" ] || continue

  if printf '%s\n' "$arp_line" | grep -q '(incomplete)'; then
    continue
  fi

  if is_private_ipv4 "$arp_ip" && ip_in_any_scanned_subnet "$arp_ip"; then
    printf '%s\n' "$arp_line" >> "$ARP_FILE"
    append_unique_line "$DISCOVERED_FILE" "$arp_ip"
  fi
done < "$ARP_RAW_FILE"

if ip_in_any_scanned_subnet "$DEFAULT_IP"; then
  append_unique_line "$DISCOVERED_FILE" "$DEFAULT_IP"
fi

if is_ipv4 "$DEFAULT_GATEWAY" && ip_in_any_scanned_subnet "$DEFAULT_GATEWAY"; then
  append_unique_line "$DISCOVERED_FILE" "$DEFAULT_GATEWAY"
fi

sort -t. -k1,1n -k2,2n -k3,3n -k4,4n "$DISCOVERED_FILE" \
  -o "$DISCOVERED_FILE"

DEVICE_TOTAL="$(wc -l < "$DISCOVERED_FILE" | tr -d ' ')"
DEVICE_INDEX=0

while IFS= read -r ip; do
  [ -n "$ip" ] || continue

  DEVICE_INDEX=$((DEVICE_INDEX + 1))
  printf '\rIdentifying device %3s of %3s: %-15s' \
    "$DEVICE_INDEX" "$DEVICE_TOTAL" "$ip"

  hostname_value="$(resolve_hostname "$ip")"
  if [ "$ip" = "$DEFAULT_IP" ] && [ -n "$DEFAULT_MAC" ]; then
    mac="$DEFAULT_MAC"
  else
    mac="$(get_arp_mac "$ip")"
  fi
  ports_csv="$(probe_tcp_ports "$ip")"
  services="$(ports_to_services "$ports_csv")"

  ping_ms="$(awk -F'\t' -v target="$ip" '$1 == target {print $2; exit}' "$ALIVE_FILE")"

  if [ -n "$ping_ms" ]; then
    reachability="ICMP reply"
  elif [ -n "$mac" ]; then
    reachability="ARP / neighbor detected"
  elif [ "$ip" = "$DEFAULT_IP" ]; then
    reachability="Local Mac"
  elif [ "$ip" = "$DEFAULT_GATEWAY" ]; then
    reachability="Configured gateway"
  else
    reachability="Detected"
  fi

  if [ "$ip" = "$DEFAULT_GATEWAY" ]; then
    is_gateway="true"
  else
    is_gateway="false"
  fi

  if [ "$ip" = "$DEFAULT_IP" ]; then
    is_local="true"
  else
    is_local="false"
  fi

  likely="$(classify_device "$ip" "$ports_csv" "$is_gateway" "$is_local" "$hostname_value")"

  notes=""
  if [ -z "$ping_ms" ] && [ -n "$mac" ]; then
    notes="Host appears online but may block ICMP ping."
  fi

  if [ "$is_gateway" = "true" ]; then
    if [ -n "$notes" ]; then
      notes="$notes Configured as the default gateway on this Mac."
    else
      notes="Configured as the default gateway on this Mac."
    fi
  fi

  if [ "$is_local" = "true" ]; then
    if [ -n "$notes" ]; then
      notes="$notes Address belongs to the Mac running this report."
    else
      notes="Address belongs to the Mac running this report."
    fi
  fi

  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$(sanitize_field "$ip")" \
    "$(sanitize_field "$hostname_value")" \
    "$(sanitize_field "$mac")" \
    "$(sanitize_field "$DEFAULT_INTERFACE")" \
    "$(sanitize_field "$reachability")" \
    "$(sanitize_field "$ping_ms")" \
    "$is_gateway" \
    "$(sanitize_field "$likely")" \
    "$(sanitize_field "$services")" \
    "$(sanitize_field "$notes")" \
    >> "$DEVICES_FILE"
done < "$DISCOVERED_FILE"

printf '\n'

add_warning "Device type is an evidence-based estimate from addresses, names, gateways, and common TCP ports; it is not authenticated operating-system identification."
add_warning "Running the scan from both Windows and macOS improves visibility because sleeping hosts, local firewalls, and cached neighbor information can produce different results from each computer."
add_warning "Offline, sleeping, firewall-filtered, guest-network-isolated, Wi-Fi client-isolated, or IPv6-only devices may not appear."
add_warning "The script reports reachable services but does not determine whether software is patched or vulnerable."

COMPLETED_AT="$(date "+%Y-%m-%d %H:%M:%S %z")"
END_EPOCH="$(date +%s)"
DURATION_SECONDS=$((END_EPOCH - START_EPOCH))
DEVICE_COUNT="$(wc -l < "$DEVICES_FILE" | tr -d ' ')"
OPEN_SERVICE_COUNT="$(awk -F'|' '
  $9 != "" {
    count = split($9, services, ";")
    total += count
  }
  END { print total + 0 }
' "$DEVICES_FILE")"

write_devices_csv
write_json_report
write_text_report
write_html_report

log_message "OK" "HTML report created: $HTML_PATH"

if convert_report_to_pdf; then
  :
fi

log_message "OK" "CSV device inventory: $CSV_PATH"
log_message "OK" "JSON report data: $JSON_PATH"
log_message "OK" "Text report: $TEXT_PATH"
log_message "OK" "Log file: $LOG_PATH"
log_message "OK" "Completed. Devices discovered: $DEVICE_COUNT"

printf '\nREPORT PACKAGE\n'
printf 'PDF : %s\n' "$PDF_PATH"
printf 'HTML: %s\n' "$HTML_PATH"
printf 'CSV : %s\n' "$CSV_PATH"
printf 'JSON: %s\n' "$JSON_PATH"
printf 'TEXT: %s\n' "$TEXT_PATH"
printf 'LOG : %s\n\n' "$LOG_PATH"

if [ "$OPEN_REPORT" -eq 1 ]; then
  if [ -s "$PDF_PATH" ]; then
    open "$PDF_PATH"
  else
    open "$HTML_PATH"
  fi
fi

exit 0

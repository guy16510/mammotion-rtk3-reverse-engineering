#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef STATUS_LED_PIN
#define STATUS_LED_PIN -1
#endif

#ifndef AP_SSID
#define AP_SSID "RTK3-Probe"
#endif

#ifndef AP_PASSWORD
#define AP_PASSWORD "rtk3-probe"
#endif

#ifndef DEVICE_HOSTNAME
#define DEVICE_HOSTNAME "rtk3-probe"
#endif

#ifndef AUTO_LAN_SCAN_ON_BOOT
#define AUTO_LAN_SCAN_ON_BOOT 1
#endif

// A scan is intentionally bounded. Home networks are normally /24; larger
// subnets are capped to the ESP32's local /24 to avoid probing thousands of IPs.
#ifndef MAX_LAN_SCAN_HOSTS
#define MAX_LAN_SCAN_HOSTS 254U
#endif

#ifndef LAN_PING_TIMEOUT_MS
#define LAN_PING_TIMEOUT_MS 150U
#endif

#ifndef LAN_TCP_TIMEOUT_MS
#define LAN_TCP_TIMEOUT_MS 80U
#endif

#ifndef MAX_PROBE_PORTS
#define MAX_PROBE_PORTS 20U
#endif

// Ports commonly associated with embedded web services, MQTT, discovery,
// diagnostics, and the 50001-50003 range observed around Mammotion devices.
static constexpr uint16_t LAN_CANDIDATE_PORTS[] = {
    22, 53, 80, 443, 554, 1883, 8883, 5000, 5001, 50001,
    50002, 50003, 5353, 8000, 8080, 8443, 9000, 10000};
static constexpr size_t LAN_CANDIDATE_PORT_COUNT =
    sizeof(LAN_CANDIDATE_PORTS) / sizeof(LAN_CANDIDATE_PORTS[0]);

// Hosts that ignore ICMP are checked only on this smaller set to keep a full
// subnet scan reasonably fast.
static constexpr uint16_t LAN_FALLBACK_PORTS[] = {
    80, 443, 1883, 8883, 50001, 50002, 50003};
static constexpr size_t LAN_FALLBACK_PORT_COUNT =
    sizeof(LAN_FALLBACK_PORTS) / sizeof(LAN_FALLBACK_PORTS[0]);

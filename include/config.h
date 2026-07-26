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

#ifndef AUTO_TARGET_PROBE_ON_BOOT
#define AUTO_TARGET_PROBE_ON_BOOT 1
#endif

#ifndef TARGET_PING_TIMEOUT_MS
#define TARGET_PING_TIMEOUT_MS 700U
#endif

#ifndef TARGET_TCP_TIMEOUT_MS
#define TARGET_TCP_TIMEOUT_MS 800U
#endif

#ifndef TARGET_BANNER_WAIT_MS
#define TARGET_BANNER_WAIT_MS 500U
#endif

#ifndef MAX_BANNER_BYTES
#define MAX_BANNER_BYTES 768U
#endif

#ifndef MAX_PROBE_PORTS
#define MAX_PROBE_PORTS 24U
#endif

// Direct checks for the known RTK3. These cover common embedded web, MQTT,
// NTRIP/GNSS, discovery, diagnostics, and Mammotion-adjacent service ranges.
static constexpr uint16_t DEFAULT_TARGET_PORTS[] = {
    22, 53, 80, 443, 554, 123, 1883, 2101, 5000, 5001, 5353, 8000,
    8080, 8443, 8883, 9000, 10000, 50001, 50002, 50003};
static constexpr size_t DEFAULT_TARGET_PORT_COUNT =
    sizeof(DEFAULT_TARGET_PORTS) / sizeof(DEFAULT_TARGET_PORTS[0]);

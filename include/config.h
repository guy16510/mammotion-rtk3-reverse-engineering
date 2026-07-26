#pragma once

#include <stdint.h>

// Receive-only connection. Connect RTK TX to this pin and share GND.
// Never connect an ESP32 TX pin to the RTK while passively probing.
#ifndef RTK_RX_PIN
#define RTK_RX_PIN 18
#endif

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

#ifndef CAPTURE_SECONDS_PER_BAUD
#define CAPTURE_SECONDS_PER_BAUD 12
#endif

#ifndef MAX_CAPTURE_SECONDS_PER_BAUD
#define MAX_CAPTURE_SECONDS_PER_BAUD 60
#endif

// Eight baud samples at 64 KiB each fit comfortably in the default LittleFS
// partition. Increase only after selecting a larger filesystem partition or SD.
#ifndef MAX_CAPTURE_BYTES_PER_BAUD
#define MAX_CAPTURE_BYTES_PER_BAUD (64U * 1024U)
#endif

#ifndef MAX_PROBE_PORTS
#define MAX_PROBE_PORTS 16
#endif

#ifndef TCP_CONNECT_TIMEOUT_MS
#define TCP_CONNECT_TIMEOUT_MS 500
#endif

static constexpr uint32_t RTK_BAUD_RATES[] = {
    9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600};
static constexpr size_t RTK_BAUD_RATE_COUNT =
    sizeof(RTK_BAUD_RATES) / sizeof(RTK_BAUD_RATES[0]);

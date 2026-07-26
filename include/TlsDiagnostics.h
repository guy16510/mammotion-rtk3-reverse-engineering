#pragma once

#include <errno.h>
#include <stdint.h>

namespace TlsDiagnostics {

inline bool isAllowedPrivateIpv4(uint8_t a, uint8_t b, uint8_t, uint8_t) {
  return a == 10 || (a == 172 && b >= 16 && b <= 31) ||
         (a == 192 && b == 168) || a == 127;
}

inline uint32_t ipv4Value(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return (static_cast<uint32_t>(a) << 24U) |
         (static_cast<uint32_t>(b) << 16U) |
         (static_cast<uint32_t>(c) << 8U) |
         static_cast<uint32_t>(d);
}

inline bool sameSubnet(uint32_t local, uint32_t target, uint32_t mask) {
  return (local & mask) == (target & mask);
}

inline const char* classifyTcpFailure(int errorCode) {
  switch (errorCode) {
    case ETIMEDOUT:
      return "timeout";
    case ECONNREFUSED:
      return "connection-refused";
    case EHOSTUNREACH:
      return "host-unreachable";
    case ENETUNREACH:
      return "network-unreachable";
    case EADDRNOTAVAIL:
      return "address-not-available";
    default:
      return errorCode == 0 ? "connect-failed-no-errno" : "connect-failed";
  }
}

inline bool shouldRetryTcp(bool connected, uint8_t attemptsMade,
                           uint8_t maximumAttempts) {
  return !connected && attemptsMade < maximumAttempts;
}

}  // namespace TlsDiagnostics

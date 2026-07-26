#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

struct ProtocolStats {
  uint64_t bytes = 0;
  uint64_t printableBytes = 0;
  uint32_t rtcmFrames = 0;
  uint32_t rtcmCrcErrors = 0;
  uint32_t ubxSyncMarkers = 0;
  uint32_t nmeaPrefixes = 0;
  std::array<uint16_t, 16> rtcmTypes{};
  size_t rtcmTypeCount = 0;
};

class ProtocolAnalyzer {
 public:
  void reset();
  void feed(uint8_t byte);
  void feed(const uint8_t* data, size_t length);
  const ProtocolStats& stats() const { return stats_; }
  double printableRatio() const;

  static uint32_t crc24q(const uint8_t* data, size_t length);

 private:
  void feedRtcm(uint8_t byte);
  void rememberRtcmType(uint16_t type);

  ProtocolStats stats_{};
  uint8_t previousByte_ = 0;
  uint8_t nmeaState_ = 0;

  std::array<uint8_t, 1029> rtcmBuffer_{};
  size_t rtcmSize_ = 0;
  size_t rtcmExpected_ = 0;
};

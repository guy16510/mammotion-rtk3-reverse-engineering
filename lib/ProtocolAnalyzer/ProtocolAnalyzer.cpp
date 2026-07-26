#include "ProtocolAnalyzer.h"

#include <algorithm>

void ProtocolAnalyzer::reset() {
  stats_ = ProtocolStats{};
  previousByte_ = 0;
  nmeaState_ = 0;
  rtcmSize_ = 0;
  rtcmExpected_ = 0;
}

void ProtocolAnalyzer::feed(const uint8_t* data, size_t length) {
  if (!data) return;
  for (size_t i = 0; i < length; ++i) feed(data[i]);
}

void ProtocolAnalyzer::feed(uint8_t byte) {
  ++stats_.bytes;
  if ((byte >= 32 && byte <= 126) || byte == '\t' || byte == '\n' || byte == '\r') {
    ++stats_.printableBytes;
  }

  if (previousByte_ == 0xB5 && byte == 0x62) ++stats_.ubxSyncMarkers;
  previousByte_ = byte;

  switch (nmeaState_) {
    case 0: nmeaState_ = byte == '$' ? 1 : 0; break;
    case 1: nmeaState_ = byte == 'G' ? 2 : (byte == '$' ? 1 : 0); break;
    case 2:
      if (byte == 'N' || byte == 'P') {
        ++stats_.nmeaPrefixes;
        nmeaState_ = 0;
      } else {
        nmeaState_ = byte == '$' ? 1 : 0;
      }
      break;
    default: nmeaState_ = 0; break;
  }

  feedRtcm(byte);
}

double ProtocolAnalyzer::printableRatio() const {
  return stats_.bytes == 0 ? 0.0
                           : static_cast<double>(stats_.printableBytes) /
                                 static_cast<double>(stats_.bytes);
}

uint32_t ProtocolAnalyzer::crc24q(const uint8_t* data, size_t length) {
  uint32_t crc = 0;
  for (size_t i = 0; i < length; ++i) {
    crc ^= static_cast<uint32_t>(data[i]) << 16;
    for (uint8_t bit = 0; bit < 8; ++bit) {
      crc <<= 1;
      if (crc & 0x1000000U) crc ^= 0x1864CFBU;
    }
  }
  return crc & 0xFFFFFFU;
}

void ProtocolAnalyzer::feedRtcm(uint8_t byte) {
  if (rtcmSize_ == 0) {
    if (byte != 0xD3) return;
    rtcmBuffer_[0] = byte;
    rtcmSize_ = 1;
    rtcmExpected_ = 0;
    return;
  }

  if (rtcmSize_ >= rtcmBuffer_.size()) {
    rtcmSize_ = 0;
    rtcmExpected_ = 0;
    if (byte == 0xD3) {
      rtcmBuffer_[0] = byte;
      rtcmSize_ = 1;
    }
    return;
  }

  rtcmBuffer_[rtcmSize_++] = byte;

  if (rtcmSize_ == 3) {
    const uint16_t payloadLength =
        static_cast<uint16_t>(((rtcmBuffer_[1] & 0x03U) << 8U) | rtcmBuffer_[2]);
    rtcmExpected_ = 3U + payloadLength + 3U;
    if (payloadLength > 1023 || rtcmExpected_ > rtcmBuffer_.size()) {
      rtcmSize_ = 0;
      rtcmExpected_ = 0;
    }
    return;
  }

  if (rtcmExpected_ == 0 || rtcmSize_ < rtcmExpected_) return;

  const size_t crcOffset = rtcmExpected_ - 3U;
  const uint32_t expected =
      (static_cast<uint32_t>(rtcmBuffer_[crcOffset]) << 16U) |
      (static_cast<uint32_t>(rtcmBuffer_[crcOffset + 1]) << 8U) |
      static_cast<uint32_t>(rtcmBuffer_[crcOffset + 2]);
  const uint32_t actual = crc24q(rtcmBuffer_.data(), crcOffset);

  if (actual == expected) {
    ++stats_.rtcmFrames;
    if (crcOffset >= 5) {
      const uint16_t type = static_cast<uint16_t>(
          (static_cast<uint16_t>(rtcmBuffer_[3]) << 4U) |
          (static_cast<uint16_t>(rtcmBuffer_[4]) >> 4U));
      rememberRtcmType(type);
    }
  } else {
    ++stats_.rtcmCrcErrors;
  }

  rtcmSize_ = 0;
  rtcmExpected_ = 0;
}

void ProtocolAnalyzer::rememberRtcmType(uint16_t type) {
  const auto begin = stats_.rtcmTypes.begin();
  const auto end = begin + static_cast<std::ptrdiff_t>(stats_.rtcmTypeCount);
  if (std::find(begin, end, type) != end) return;
  if (stats_.rtcmTypeCount < stats_.rtcmTypes.size()) {
    stats_.rtcmTypes[stats_.rtcmTypeCount++] = type;
  }
}

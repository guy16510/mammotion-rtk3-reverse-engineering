#include <unity.h>

#include "ProtocolAnalyzer.h"

void test_crc24q_known_rtcm_frame() {
  const uint8_t frame[] = {0xD3, 0x00, 0x02, 0x3E, 0xD0, 0xA4, 0xE0, 0x00};
  TEST_ASSERT_EQUAL_HEX32(0xA4E000,
                          ProtocolAnalyzer::crc24q(frame, sizeof(frame) - 3));
}

void test_valid_rtcm_frame_across_chunks() {
  ProtocolAnalyzer analyzer;
  const uint8_t first[] = {0x01, 0xD3, 0x00, 0x02};
  const uint8_t second[] = {0x3E, 0xD0, 0xA4, 0xE0, 0x00, 0x02};
  analyzer.feed(first, sizeof(first));
  analyzer.feed(second, sizeof(second));

  const ProtocolStats& stats = analyzer.stats();
  TEST_ASSERT_EQUAL_UINT32(1, stats.rtcmFrames);
  TEST_ASSERT_EQUAL_UINT32(0, stats.rtcmCrcErrors);
  TEST_ASSERT_EQUAL_UINT32(1, stats.rtcmTypeCount);
  TEST_ASSERT_EQUAL_UINT16(1005, stats.rtcmTypes[0]);
}

void test_bad_rtcm_crc_is_rejected() {
  ProtocolAnalyzer analyzer;
  const uint8_t frame[] = {0xD3, 0x00, 0x02, 0x3E, 0xD0, 0xA4, 0xE0, 0x01};
  analyzer.feed(frame, sizeof(frame));
  TEST_ASSERT_EQUAL_UINT32(0, analyzer.stats().rtcmFrames);
  TEST_ASSERT_EQUAL_UINT32(1, analyzer.stats().rtcmCrcErrors);
}

void test_ubx_and_nmea_markers() {
  ProtocolAnalyzer analyzer;
  const uint8_t bytes[] = {'x', 0xB5, 0x62, '$', 'G', 'N', 'G', 'G', 'A', '\r', '\n',
                           '$', 'G', 'P', 'R', 'M', 'C'};
  analyzer.feed(bytes, sizeof(bytes));
  TEST_ASSERT_EQUAL_UINT32(1, analyzer.stats().ubxSyncMarkers);
  TEST_ASSERT_EQUAL_UINT32(2, analyzer.stats().nmeaPrefixes);
  TEST_ASSERT_GREATER_THAN(0.5, analyzer.printableRatio());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_crc24q_known_rtcm_frame);
  RUN_TEST(test_valid_rtcm_frame_across_chunks);
  RUN_TEST(test_bad_rtcm_crc_is_rejected);
  RUN_TEST(test_ubx_and_nmea_markers);
  return UNITY_END();
}

#include <unity.h>

#include <errno.h>

#include "TlsDiagnostics.h"

void test_private_ipv4_ranges_are_allowed() {
  TEST_ASSERT_TRUE(TlsDiagnostics::isAllowedPrivateIpv4(10, 0, 0, 1));
  TEST_ASSERT_TRUE(TlsDiagnostics::isAllowedPrivateIpv4(172, 16, 0, 1));
  TEST_ASSERT_TRUE(TlsDiagnostics::isAllowedPrivateIpv4(172, 31, 255, 254));
  TEST_ASSERT_TRUE(TlsDiagnostics::isAllowedPrivateIpv4(192, 168, 2, 26));
  TEST_ASSERT_TRUE(TlsDiagnostics::isAllowedPrivateIpv4(127, 0, 0, 1));
}

void test_non_private_ipv4_ranges_are_rejected() {
  TEST_ASSERT_FALSE(TlsDiagnostics::isAllowedPrivateIpv4(8, 8, 8, 8));
  TEST_ASSERT_FALSE(TlsDiagnostics::isAllowedPrivateIpv4(169, 254, 1, 1));
  TEST_ASSERT_FALSE(TlsDiagnostics::isAllowedPrivateIpv4(172, 15, 255, 255));
  TEST_ASSERT_FALSE(TlsDiagnostics::isAllowedPrivateIpv4(172, 32, 0, 0));
  TEST_ASSERT_FALSE(TlsDiagnostics::isAllowedPrivateIpv4(192, 167, 1, 1));
}

void test_same_subnet_uses_the_supplied_mask() {
  const uint32_t local = TlsDiagnostics::ipv4Value(192, 168, 2, 43);
  const uint32_t peer = TlsDiagnostics::ipv4Value(192, 168, 2, 26);
  const uint32_t other = TlsDiagnostics::ipv4Value(192, 168, 3, 26);
  const uint32_t mask = TlsDiagnostics::ipv4Value(255, 255, 255, 0);

  TEST_ASSERT_TRUE(TlsDiagnostics::sameSubnet(local, peer, mask));
  TEST_ASSERT_FALSE(TlsDiagnostics::sameSubnet(local, other, mask));
}

void test_tcp_errno_classification() {
  TEST_ASSERT_EQUAL_STRING("timeout",
                           TlsDiagnostics::classifyTcpFailure(ETIMEDOUT));
  TEST_ASSERT_EQUAL_STRING("connection-refused",
                           TlsDiagnostics::classifyTcpFailure(ECONNREFUSED));
  TEST_ASSERT_EQUAL_STRING("host-unreachable",
                           TlsDiagnostics::classifyTcpFailure(EHOSTUNREACH));
  TEST_ASSERT_EQUAL_STRING("network-unreachable",
                           TlsDiagnostics::classifyTcpFailure(ENETUNREACH));
  TEST_ASSERT_EQUAL_STRING("address-not-available",
                           TlsDiagnostics::classifyTcpFailure(EADDRNOTAVAIL));
  TEST_ASSERT_EQUAL_STRING("connect-failed-no-errno",
                           TlsDiagnostics::classifyTcpFailure(0));
  TEST_ASSERT_EQUAL_STRING("connect-failed",
                           TlsDiagnostics::classifyTcpFailure(123456));
}

void test_tcp_retry_stops_after_success() {
  TEST_ASSERT_TRUE(TlsDiagnostics::shouldRetryTcp(false, 1, 3));
  TEST_ASSERT_TRUE(TlsDiagnostics::shouldRetryTcp(false, 2, 3));
  TEST_ASSERT_FALSE(TlsDiagnostics::shouldRetryTcp(false, 3, 3));
  TEST_ASSERT_FALSE(TlsDiagnostics::shouldRetryTcp(true, 1, 3));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_private_ipv4_ranges_are_allowed);
  RUN_TEST(test_non_private_ipv4_ranges_are_rejected);
  RUN_TEST(test_same_subnet_uses_the_supplied_mask);
  RUN_TEST(test_tcp_errno_classification);
  RUN_TEST(test_tcp_retry_stops_after_success);
  return UNITY_END();
}

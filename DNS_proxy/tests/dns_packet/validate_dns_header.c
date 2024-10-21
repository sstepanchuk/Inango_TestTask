#include <check.h>
#include "main.h"

// Test for a valid DNS header
START_TEST(valid_dns_header) {
  DnsHeader header = {0};
  header.id = 1;
  header.qr = 0;      // Query
  header.q_count = 1; // At least one question
  header.ans_count = 0;
  header.auth_count = 0;
  header.add_count = 0;
  header.tc = 0;     // Not truncated
  header.opcode = 0; // Standard query
  header.rcode = 0;  // No error

  int result = validate_dns_header(&header, sizeof(header));
  ck_assert_int_eq(result, 1); // Should be valid
}
END_TEST

// Test for too small packet size
START_TEST(too_small_packet) {
  DnsHeader header = {0};
  int result = validate_dns_header(&header, sizeof(header) - 1);
  ck_assert_int_eq(result, 0); // Should be invalid
}
END_TEST

// Test for reserved bit not being zero
START_TEST(reserved_bit_non_zero) {
  DnsHeader header = {0};
  header.z = 1; // Reserved bit should be zero
  int result = validate_dns_header(&header, sizeof(header));
  ck_assert_int_eq(result, 0); // Should be invalid
}
END_TEST

// Test for response with queries
START_TEST(response_with_queries) {
  DnsHeader header = {0};
  header.qr = 1;      // Response
  header.q_count = 1; // Should be zero for response
  header.ans_count = 1;
  int result = validate_dns_header(&header, sizeof(header));
  ck_assert_int_eq(result, 0); // Should be invalid
}
END_TEST

// Add these tests to the test suite
TCase *test__validate_dns_header(void) {
  TCase *tc_core = tcase_create("validate_dns_header");
  tcase_add_test(tc_core, valid_dns_header);
  tcase_add_test(tc_core, too_small_packet);
  tcase_add_test(tc_core, reserved_bit_non_zero);
  tcase_add_test(tc_core, response_with_queries);
  return tc_core;
}

#include <check.h>
#include "./main.h"

// Test for serializing a valid domain name
START_TEST(test_serialize_valid_domain_name) {
  unsigned char packet[MAX_DNS_PACKET_SIZE];
  const char *domain_name = "example.com";
  int pos = serialize_domain_name(domain_name, packet, 0);

  ck_assert_int_eq(pos, 13);
  ck_assert_int_eq(packet[0], 7);
  ck_assert_mem_eq(packet + 1, "example", 7);
  ck_assert_int_eq(packet[8], 3);
  ck_assert_mem_eq(packet + 9, "com", 3);
  ck_assert_int_eq(packet[12], 0);
}
END_TEST

// Test for serializing an empty domain name
START_TEST(test_serialize_empty_domain_name) {
  unsigned char packet[MAX_DNS_PACKET_SIZE];
  const char *domain_name = "";
  int pos = serialize_domain_name(domain_name, packet, 0);

  ck_assert_int_eq(pos, 2);       // Should only write the null terminator
  ck_assert_int_eq(packet[0], 0); // Check null terminator
}
END_TEST

// Add these tests to the test suite
TCase *test__serialize_and_parse_domain_name(void) {
  TCase *tc_core = tcase_create("serialize_and_parse_domain_name");
  tcase_add_test(tc_core, test_serialize_valid_domain_name);
  tcase_add_test(tc_core, test_serialize_empty_domain_name);
  return tc_core;
}

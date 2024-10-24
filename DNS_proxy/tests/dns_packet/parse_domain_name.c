#include "./main.h"

// Test with a valid domain name
START_TEST(valid_domain_name) {
  unsigned char packet[] = {0x03, 'w', 'w', 'w',  0x07, 'e', 'x', 'a', 'm',
                            'p',  'l', 'e', 0x03, 'c',  'o', 'm', 0x00};
  char *name = NULL;
  int pos = 0;
  ck_assert_int_eq(parse_domain_name(packet, sizeof(packet), &pos, &name), 0);
  ck_assert_str_eq(name, "www.example.com");
  ck_assert_int_eq(pos, 17); // Correct position after domain name
  free(name);
}
END_TEST

// Test with an invalid compressed domain name (invalid input)
START_TEST(invalid_domain_name) {
  unsigned char packet[] = {0xC0, 0x0C}; // Invalid compressed format
  char *name = NULL;

  int pos = 0;
  ck_assert_int_eq(parse_domain_name(packet, sizeof(packet), &pos, &name), -1);
  ck_assert_ptr_eq(name, NULL); // Name should remain NULL
}
END_TEST

// Test with an empty packet (boundary test)
START_TEST(empty_packet) {
  unsigned char packet[] = {0x00}; // No domain name present
  char *name = NULL;

  int pos = 0;
  ck_assert_int_eq(parse_domain_name(packet, sizeof(packet), &pos, &name), -1);
  free(name);
}
END_TEST

// Test with a domain name that exceeds maximum length
START_TEST(overlength_label) {
  unsigned char packet[] = {0x40, 'a', 'a', 'a'}; // Invalid label length (64)
  char *name = NULL;

  int pos = 0;
  ck_assert_int_eq(parse_domain_name(packet, sizeof(packet), &pos, &name), -1);
  ck_assert_ptr_eq(name, NULL); // Name should remain NULL
}
END_TEST

// Test with a valid domain name
START_TEST(packet_too_small) {
  unsigned char packet[] = {0x20, 'w', 'w', 'w'};
  char *name = NULL;

  int pos = 0;
  ck_assert_int_eq(parse_domain_name(packet, sizeof(packet), &pos, &name), -1);
  free(name);
}
END_TEST

// Add these tests to the test suite
TCase *test__parse_domain_name(void) {
  TCase *tc_core = tcase_create("parse_domain_name");
  tcase_add_test(tc_core, valid_domain_name);
  tcase_add_test(tc_core, invalid_domain_name);
  tcase_add_test(tc_core, empty_packet);
  tcase_add_test(tc_core, overlength_label);
  tcase_add_test(tc_core, packet_too_small);
  return tc_core;
}

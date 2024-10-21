#include "./main.h"

// Test with a valid domain name
START_TEST(test_valid_domain_name) {
  unsigned char packet[] = {0x03, 'w', 'w', 'w',  0x07, 'e', 'x', 'a', 'm',
                            'p',  'l', 'e', 0x03, 'c',  'o', 'm', 0x00};
  char *name = NULL;

  int pos = parse_domain_name(packet, 17, 0, &name);
  ck_assert_str_eq(name, "www.example.com");
  ck_assert_int_eq(pos, 17); // Correct position after domain name
  free(name);
}
END_TEST

// Test with an invalid compressed domain name (invalid input)
START_TEST(test_invalid_domain_name) {
  unsigned char packet[] = {0xC0, 0x0C}; // Invalid compressed format
  char *name = NULL;

  int pos = parse_domain_name(packet, sizeof(packet), 0, &name);
  ck_assert_int_eq(pos, -1);    // Should return -1 for failure
  ck_assert_ptr_eq(name, NULL); // Name should remain NULL
}
END_TEST

// Test with an empty packet (boundary test)
START_TEST(test_empty_packet) {
  unsigned char packet[] = {0x00}; // No domain name present
  char *name = NULL;

  int pos = parse_domain_name(packet, 1, 0, &name);
  ck_assert_str_eq(name, ""); // Empty domain name
  ck_assert_int_eq(pos, 1);   // Position should move past the null byte
  free(name);
}
END_TEST

// Test with a domain name that exceeds maximum length
START_TEST(test_overlength_label) {
  unsigned char packet[] = {0x40, 'a', 'a', 'a'}; // Invalid label length (64)
  char *name = NULL;

  int pos = parse_domain_name(packet, sizeof(packet), 0, &name);
  ck_assert_int_eq(pos, -1);    // Should return -1 for invalid label
  ck_assert_ptr_eq(name, NULL); // Name should remain NULL
}
END_TEST

// Add these tests to the test suite
TCase *test__parse_domain_name(void) {
  TCase *tc_core = tcase_create("parse_domain_name");
  tcase_add_test(tc_core, test_valid_domain_name);
  tcase_add_test(tc_core, test_invalid_domain_name);
  tcase_add_test(tc_core, test_empty_packet);
  tcase_add_test(tc_core, test_overlength_label);
  return tc_core;
}

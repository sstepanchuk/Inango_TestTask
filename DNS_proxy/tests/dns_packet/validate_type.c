#include <check.h>
#include "main.h"

// Test for a valid type
START_TEST(valid_type) {
  unsigned short valid_types[] = {TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_MX,
                                  TYPE_TXT};
  for (int i = 0; i < sizeof(valid_types) / sizeof(valid_types[0]); i++) {
    ck_assert_int_eq(validate_type(valid_types[i]), 1); // Should be valid
  }
}
END_TEST

// Test for an invalid type
START_TEST(invalid_type) {
  unsigned short invalid_types[] = {0x0000, 0xFFFF, 0x0011};
  for (int i = 0; i < sizeof(invalid_types) / sizeof(invalid_types[0]); i++) {
    ck_assert_int_eq(validate_type(invalid_types[i]), 0); // Should be invalid
  }
}
END_TEST

// Add these tests to the test suite
TCase *test__validate_type(void) {
  TCase *tc_core = tcase_create("validate_type");
  tcase_add_test(tc_core, valid_type);
  tcase_add_test(tc_core, invalid_type);
  return tc_core;
}

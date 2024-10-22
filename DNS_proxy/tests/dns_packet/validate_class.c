#include <check.h>
#include "main.h"

// Test for a valid class
START_TEST(valid_class) {
  unsigned short valid_classes[] = {DNS_CLASS_IN, DNS_CLASS_CS, DNS_CLASS_CH,
                                    DNS_CLASS_HS};
  for (int i = 0; i < sizeof(valid_classes) / sizeof(valid_classes[0]); i++) {
    ck_assert_int_eq(validate_class(valid_classes[i]), 1); // Should be valid
  }
}
END_TEST

// Test for an invalid class
START_TEST(invalid_class) {
  unsigned short invalid_classes[] = {0x0000, 0xFFFF, 0x0005};
  for (int i = 0; i < sizeof(invalid_classes) / sizeof(invalid_classes[0]);
       i++) {
    ck_assert_int_eq(validate_class(invalid_classes[i]),
                     0); // Should be invalid
  }
}
END_TEST

// Add these tests to the test suite
TCase *test__validate_class(void) {
  TCase *tc_core = tcase_create("validate_class");
  tcase_add_test(tc_core, valid_class);
  tcase_add_test(tc_core, invalid_class);
  return tc_core;
}

#include <check.h>
#include "main.h"

// Test for a valid QCLASS
START_TEST(valid_qclass) {
  unsigned short valid_qclasses[] = {DNS_QCLASS_ANY, DNS_CLASS_IN};
  for (int i = 0; i < sizeof(valid_qclasses) / sizeof(valid_qclasses[0]); i++) {
    ck_assert_int_eq(validate_qclass(valid_qclasses[i]), 1); // Should be valid
  }
}
END_TEST

// Test for an invalid QCLASS
START_TEST(invalid_qclass) {
  unsigned short invalid_qclasses[] = {0x0000, 0xFFFF, 0x0005};
  for (int i = 0; i < sizeof(invalid_qclasses) / sizeof(invalid_qclasses[0]);
       i++) {
    ck_assert_int_eq(validate_qclass(invalid_qclasses[i]),
                     0); // Should be invalid
  }
}
END_TEST

// Add these tests to the test suite
TCase *test__validate_qclass(void) {
  TCase *tc_core = tcase_create("validate_qclass");
  tcase_add_test(tc_core, valid_qclass);
  tcase_add_test(tc_core, invalid_qclass);
  return tc_core;
}

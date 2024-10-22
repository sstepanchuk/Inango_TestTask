#include <check.h>
#include "main.h"

// Test for a valid QTYPE
START_TEST(valid_qtype) {
  unsigned short valid_qtypes[] = {DNS_QTYPE_AXFR, DNS_QTYPE_ANY, DNS_TYPE_A,
                                   DNS_TYPE_NS};
  for (int i = 0; i < sizeof(valid_qtypes) / sizeof(valid_qtypes[0]); i++) {
    ck_assert_int_eq(validate_qtype(valid_qtypes[i]), 1); // Should be valid
  }
}
END_TEST

// Test for an invalid QTYPE
START_TEST(invalid_qtype) {
  unsigned short invalid_qtypes[] = {0x0000, 0xFFFF, 0x0011};
  for (int i = 0; i < sizeof(invalid_qtypes) / sizeof(invalid_qtypes[0]); i++) {
    ck_assert_int_eq(validate_qtype(invalid_qtypes[i]), 0); // Should be invalid
  }
}
END_TEST

// Add these tests to the test suite
TCase *test__validate_qtype(void) {
  TCase *tc_core = tcase_create("validate_qtype");
  tcase_add_test(tc_core, valid_qtype);
  tcase_add_test(tc_core, invalid_qtype);
  return tc_core;
}

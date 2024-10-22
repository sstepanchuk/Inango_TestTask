#include <check.h>
#include "./main.h"

// Test for a valid label
START_TEST(valid_label) {
  const unsigned char label[] = "example"; // Valid label
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 1); // Should return 1 (valid)
}
END_TEST

// Test for a valid label with dashes in the middle
START_TEST(valid_label_with_dashes) {
  const unsigned char label[] = "ex-ample"; // Valid label with dash
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 1); // Should return 1 (valid)
}
END_TEST

// Test for an invalid label starting with a dash
START_TEST(invalid_label_starting_with_dash) {
  const unsigned char label[] = "-example"; // Invalid label
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 0); // Should return 0 (invalid)
}
END_TEST

// Test for an invalid label ending with a dash
START_TEST(invalid_label_ending_with_dash) {
  const unsigned char label[] = "example-"; // Invalid label
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 0); // Should return 0 (invalid)
}
END_TEST

// Test for an invalid label containing invalid characters
START_TEST(invalid_label_with_special_characters) {
  const unsigned char label[] =
      "ex!ample"; // Invalid label with special character
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 0); // Should return 0 (invalid)
}
END_TEST

// Test for a label that is empty
START_TEST(empty_label) {
  const unsigned char label[] = ""; // Empty label
  int result = validate_label(label, 0);
  ck_assert_int_eq(result, 0); // Should return 0 (invalid)
}
END_TEST

// Test for a label with a single character
START_TEST(single_character_label) {
  const unsigned char label[] = "a"; // Valid single character label
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 1); // Should return 1 (valid)
}
END_TEST

// Test for a label with digits only
START_TEST(label_with_digits_only) {
  const unsigned char label[] = "123456"; // Valid label with digits only
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 1); // Should return 1 (valid)
}
END_TEST

// Test for a label with mixed characters (valid)
START_TEST(label_with_mixed_valid_characters) {
  const unsigned char label[] = "abc-123"; // Valid mixed label
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 1); // Should return 1 (valid)
}
END_TEST

// Test for a label with spaces
START_TEST(invalid_label_with_spaces) {
  const unsigned char label[] = "ex ample"; // Invalid label with space
  int result = validate_label(label, strlen((const char *)label));
  ck_assert_int_eq(result, 0); // Should return 0 (invalid)
}
END_TEST

// Function to create a test suite
TCase *test__validate_label(void) {
  TCase *tc_core = tcase_create("validate_label");
  tcase_add_test(tc_core, valid_label);
  tcase_add_test(tc_core, valid_label_with_dashes);
  tcase_add_test(tc_core, invalid_label_starting_with_dash);
  tcase_add_test(tc_core, invalid_label_ending_with_dash);
  tcase_add_test(tc_core, invalid_label_with_special_characters);
  tcase_add_test(tc_core, empty_label);
  tcase_add_test(tc_core, single_character_label);
  tcase_add_test(tc_core, label_with_digits_only);
  tcase_add_test(tc_core, label_with_mixed_valid_characters);
  tcase_add_test(tc_core, invalid_label_with_spaces);
  return tc_core;
}

#include "check_pretty_print.h"

void print_test_results_tree(SRunner *sr) {
  List *suites = sr->slst;
  check_list_front(suites);

  // Traverse all suites
  while (!check_list_at_end(suites)) {
    Suite *suite = (Suite *)check_list_val(suites);
    printf("Suite: %s\n", suite->name);

    List *test_cases = suite->tclst;
    check_list_front(test_cases);

    // Traverse all test cases in the suite
    while (!check_list_at_end(test_cases)) {
      TCase *tc = (TCase *)check_list_val(test_cases);
      printf("├── Case: %s\n", tc->name);

      List *tests = tc->tflst;
      check_list_front(tests);

      // Traverse all tests in the test case
      while (!check_list_at_end(tests)) {
        TF *test_function = (TF *)check_list_val(tests);
        const char *test_name = test_function->ttest->name;

        // Determine the test result
        List *results = sr->resultlst;
        check_list_front(results);
        const char *result_color = GREEN;
        const char *result_str = "PASSED";
        char *error_msg = NULL;
        const char *file = NULL;
        int line = 0;

        while (!check_list_at_end(results)) {
          TestResult *result = (TestResult *)check_list_val(results);
          if (strcmp(result->tname, test_name) == 0 &&
              result->rtype != CK_PASS) {
            result_color = RED;
            result_str = "FAILED";
            error_msg = result->msg; // Capture the error message
            file = result->file;     // Capture the file name
            line = result->line;     // Capture the line number
            break;
          }
          check_list_advance(results);
        }

        // Print the test result with color
        printf("│   └── %s [%s%s%s]\n", test_name, result_color, result_str,
               RESET);

        if (error_msg) {
          const char *filename =
              strrchr(file, '/'); // Get the last part after '/'
          filename = (filename) ? filename + 1 : file; // Move past '/'
          printf("│       └── Error: %s:%d: %s\n", filename, line, error_msg);
        }
        check_list_advance(tests);
      }

      check_list_advance(test_cases);
    }

    check_list_advance(suites);
  }
}
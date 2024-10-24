#include "check/check_pretty_print.h"
#include "./dns_packet/main.h"

int main(void) {
  int number_failed;
  SRunner *sr;
  sr = srunner_create(dns_packet_suite());
  srunner_set_fork_status(sr, CK_NOFORK);
  srunner_run_all(sr, CK_MINIMAL);

  print_test_results_tree(sr);

  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

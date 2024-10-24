
#include "./main.h"

Suite *dns_packet_suite(void) {
  Suite *s;
  TCase *tc_core;

  s = suite_create("dns_packet");
  suite_add_tcase(s, test__validate_dns_header());
  suite_add_tcase(s, test__validate_type());
  suite_add_tcase(s, test__validate_class());
  suite_add_tcase(s, test__validate_qtype());
  suite_add_tcase(s, test__validate_qclass());
  suite_add_tcase(s, test__validate_label());
  suite_add_tcase(s, test__parse_domain_name());
  suite_add_tcase(s, test__parse_dns_queries());
  suite_add_tcase(s, test__serialize_and_parse_domain_name());
  suite_add_tcase(s, test__parse_dns_packet());
  return s;
}
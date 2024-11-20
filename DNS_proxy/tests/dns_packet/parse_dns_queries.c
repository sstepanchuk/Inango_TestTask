#include <check.h>
#include "./main.h"

// Test for successful parsing of DNS queries
START_TEST(successful_parse) {
  unsigned char packet[] = {
      0x03, 'w',  'w', 'w',                      // "www"
      0x07, 'e',  'x', 'a', 'm',  'p', 'l', 'e', // "example"
      0x03, 'c',  'o', 'm', 0x00,                // "com"
      0x00, 0x01,                                // QTYPE A
      0x00, 0x01                                 // QCLASS IN
  };
  DnsQuery *queries = NULL;
  unsigned short count = 1;
  int pos = parse_dns_queries(packet, &queries, sizeof(packet), 0, count);

  ck_assert_int_eq(pos,
                   sizeof(packet)); // Position should be at the end of packet

  // Validate the parsed query
  ck_assert_str_eq(queries[0].name, "www.example.com");
  ck_assert_int_eq(queries[0].ques.qtype, DNS_TYPE_A);
  ck_assert_int_eq(queries[0].ques.qclass, DNS_CLASS_IN);

  // Free allocated memory
  free(queries[0].name);
  free(queries);
}
END_TEST

// Test for parsing failure due to invalid query data
START_TEST(invalid_query_data) {
  unsigned char packet[] = {
      0x03, 'w',  'w', 'w',                      // "www"
      0x07, 'e',  'x', 'a', 'm',  'p', 'l', 'e', // "example"
      0x03, 'c',  'o', 'm', 0x00,                // "com"
      0x00, 0x01,                                // QTYPE A
      0xFF, 0x00                                 // Invalid QCLASS
  };
  DnsQuery *queries = NULL;
  unsigned short count = 1;
  int pos = parse_dns_queries(packet, &queries, sizeof(packet), pos, count);

  ck_assert_int_eq(pos, -1); // Should fail due to invalid QCLASS
}
END_TEST

// Test for parsing failure due to invalid packet size
START_TEST(packet_size_too_small) {
  unsigned char packet[] = {
      0x03, 'w',  'w', 'w',                      // "www"
      0x07, 'e',  'x', 'a', 'm',  'p', 'l', 'e', // "example"
      0x03, 'c',  'o', 'm', 0x00,                // "com"
      0x00, 0x01,                                // QTYPE A
      0x00                                       // Incomplete data (too small)
  };
  DnsQuery *queries = NULL;

  unsigned short count = 1;
  int pos = parse_dns_queries(packet, &queries, sizeof(packet), pos, count);
  ck_assert_int_eq(pos, -1); // Should fail due to packet size
}
END_TEST

// Add these tests to the test suite
TCase *test__parse_dns_queries(void) {
  TCase *tc_core = tcase_create("parse_dns_queries");
  tcase_add_test(tc_core, successful_parse);
  tcase_add_test(tc_core, invalid_query_data);
  tcase_add_test(tc_core, packet_size_too_small);
  return tc_core;
}

#include <check.h>
#include "./main.h"

// Test for successful parsing of DNS queries
START_TEST(query_successful_parse_example_com) {
  const char dns_query[] = {
      0x12, 0x34, // Transaction ID: 0x1234
      0x01, 0x00, // Flags: standard query (0x0100)
      0x00, 0x01, // Questions: 1
      0x00, 0x00, // Answer RRs: 0
      0x00, 0x00, // Authority RRs: 0
      0x00, 0x00, // Additional RRs: 0
      0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', // "example" domain label
      0x03, 'c',  'o', 'm',                     // "com" domain label
      0x00,                                     // End of domain name
      0x00, 0x01,                               // Type: A (IPv4 address)
      0x00, 0x01                                // Class: IN (Internet)
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_nonnull(packet);
  ck_assert_int_eq(packet->header.id, 0x1234);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_successful_parse_example_org_aaaa) {
  const char dns_query[] = {
      0x56, 0x78,                               // Transaction ID: 0x5678
      0x01, 0x00,                               // Flags: standard query
      0x00, 0x01,                               // Questions: 1
      0x00, 0x00,                               // Answer RRs: 0
      0x00, 0x00,                               // Authority RRs: 0
      0x00, 0x00,                               // Additional RRs: 0
      0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', // "example" domain label
      0x03, 'o',  'r', 'g',                     // "org" domain label
      0x00,                                     // End of domain name
      0x00, 0x1c,                               // Type: AAAA (IPv6 address)
      0x00, 0x01                                // Class: IN (Internet)
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_nonnull(packet);

  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_successful_parse_example_net_mx) {
  const char dns_query[] = {
      0xab, 0xcd,                               // Transaction ID: 0xabcd
      0x01, 0x00,                               // Flags: standard query
      0x00, 0x01,                               // Questions: 1
      0x00, 0x00,                               // Answer RRs: 0
      0x00, 0x00,                               // Authority RRs: 0
      0x00, 0x00,                               // Additional RRs: 0
      0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', // "example" domain label
      0x03, 'n',  'e', 't',                     // "net" domain label
      0x00,                                     // End of domain name
      0x00, 0x0f,                               // Type: MX (Mail exchange)
      0x00, 0x01                                // Class: IN (Internet)
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_nonnull(packet);

  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_successful_parse_example_edu_ptr) {
  const char dns_query[] = {
      0x11, 0x11,                               // Transaction ID: 0x1111
      0x01, 0x00,                               // Flags: standard query
      0x00, 0x01,                               // Questions: 1
      0x00, 0x00,                               // Answer RRs: 0
      0x00, 0x00,                               // Authority RRs: 0
      0x00, 0x00,                               // Additional RRs: 0
      0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', // "example" domain label
      0x03, 'e',  'd', 'u',                     // "edu" domain label
      0x00,                                     // End of domain name
      0x00, 0x0c,                               // Type: PTR (0x000c)
      0x00, 0x01                                // Class: IN (Internet)
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_nonnull(packet);

  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_incorrect_domain_format) {
  const char dns_query[] = {
      0x12, 0x34, // Transaction ID: 0x1234
      0x01, 0x00, // Flags: standard query
      0x00, 0x01, // Questions: 1
      0x00, 0x00, // Answer RRs: 0
      0x00, 0x00, // Authority RRs: 0
      0x00, 0x00, // Additional RRs: 0
      0x03, 'e',  'x', 'a',
      'm',  'p',  'l', 'e', // Incorrect: no length before "example"
      0x03, 'c',  'o', 'm', // "com" domain label
      0x00,                 // End of domain name
      0x00, 0x01,           // Type: A
      0x00, 0x01            // Class: IN
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_null(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_incorrect_query_type) {
  const char dns_query[] = {
      0x56, 0x78,                              // Transaction ID: 0x5678
      0x01, 0x00,                              // Flags: standard query
      0x00, 0x01,                              // Questions: 1
      0x00, 0x00,                              // Answer RRs: 0
      0x00, 0x00,                              // Authority RRs: 0
      0x00, 0x00,                              // Additional RRs: 0
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example" domain label
      0x03, 'o', 'r', 'g',                     // "org" domain label
      0x00,                                    // End of domain name
      0x00, 0x99, // Incorrect query type (should be 0x0001 for A, 0x001c for
                  // AAAA)
      0x00, 0x01  // Class: IN (Internet)
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_null(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_incorrect_flags) {
  const char dns_query[] = {
      0x12, 0x34,                               // Transaction ID: 0x1234
      0xFF, 0xFF,                               // Incorrect flags
      0x00, 0x01,                               // Questions: 1
      0x00, 0x00,                               // Answer RRs: 0
      0x00, 0x00,                               // Authority RRs: 0
      0x00, 0x00,                               // Additional RRs: 0
      0x07, 'e',  'x', 'a', 'm', 'p', 'l', 'e', // "example" domain label
      0x03, 'c',  'o', 'm',                     // "com" domain label
      0x00,                                     // End of domain name
      0x00, 0x01,                               // Type: A
      0x00, 0x01                                // Class: IN (Internet)
  };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_null(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(query_incorrect_longdomain) {
  const char
      dns_query[] =
          {
              0x12, 0x34, // Transaction ID: 0x1234
              0x01, 0x00, // Flags: standard query
              0x00, 0x01, // Questions: 1
              0x00, 0x00, // Answer RRs: 0
              0x00, 0x00, // Authority RRs: 0
              0x00, 0x00, // Additional RRs: 0
              0x20, 'a',  'b', 'c', 'd',  'e', 'f', 'g',
              'h',  'i',  'j', // Invalid length (32 bytes, too long)
              'k',  'l',  'm', 'n', 'o',  'p', 'q', 'r',
              's',  't',  'u', 'v', 'w',  'x', 'y', 'z',
              '1',  '2',  '3', '4', 0x03, 'c', 'o', 'm', // "com" domain label
              0x00,                                      // End of domain name
              0x00, 0x01,                                // Type: A
              0x00, 0x01                                 // Class: IN
          };

  DnsPacket *packet = parse_dns_packet(dns_query, sizeof(dns_query));

  ck_assert_ptr_null(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

// Responses

START_TEST(response_correct_a) {
  const char dns_response[] = {
      0x12, 0x34, // Transaction ID
      0x81, 0x80, // Flags: standard query response, no error (0x8180)
      0x00, 0x01, // Questions: 1
      0x00, 0x01, // Answer RRs: 1
      0x00, 0x00, // Authority RRs: 0
      0x00, 0x00, // Additional RRs: 0
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
      0x03, 'c', 'o', 'm',                     // "com"
      0x00,                                    // End of domain name
      0x00, 0x01,                              // Type: A
      0x00, 0x01,                              // Class: IN
      // Answer section starts
      0xc0,
      0x0c, // Name: pointer to offset 0x0c (the "example.com" in the question)
      0x00, 0x01,             // Type: A
      0x00, 0x01,             // Class: IN
      0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
      0x00, 0x04,             // Data length: 4 bytes (IPv4 address)
      0xc0, 0xa8, 0x00, 0x01  // Address: 192.168.0.1
  };

  DnsPacket *packet = parse_dns_packet(dns_response, sizeof(dns_response));

  ck_assert_ptr_nonnull(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(response_correct_aaaa) {
  const char dns_response[] = {
      0x56, 0x78, // Transaction ID
      0x81, 0x80, // Flags: standard query response, no error (0x8180)
      0x00, 0x01, // Questions: 1
      0x00, 0x01, // Answer RRs: 1
      0x00, 0x00, // Authority RRs: 0
      0x00, 0x00, // Additional RRs: 0
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
      0x03, 'o', 'r', 'g',                     // "org"
      0x00,                                    // End of domain name
      0x00, 0x1c,                              // Type: AAAA
      0x00, 0x01,                              // Class: IN
      // Answer section starts
      0xc0,
      0x0c, // Name: pointer to offset 0x0c (the "example.org" in the question)
      0x00, 0x1c,             // Type: AAAA
      0x00, 0x01,             // Class: IN
      0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
      0x00, 0x10,             // Data length: 16 bytes (IPv6 address)
      0x20, 0x01, 0x0d,
      0xb8, // Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
      0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34};

  DnsPacket *packet = parse_dns_packet(dns_response, sizeof(dns_response));

  ck_assert_ptr_nonnull(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

START_TEST(response_correct_mx) {
  const char dns_response[] = {
      0xab, 0xcd, // Transaction ID
      0x81, 0x80, // Flags: standard query response, no error (0x8180)
      0x00, 0x01, // Questions: 1
      0x00, 0x01, // Answer RRs: 1
      0x00, 0x00, // Authority RRs: 0
      0x00, 0x00, // Additional RRs: 0
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
      0x03, 'n', 'e', 't',                     // "net"
      0x00,                                    // End of domain name
      0x00, 0x0f,                              // Type: MX
      0x00, 0x01,                              // Class: IN
      // Answer section starts
      0xc0,
      0x0c, // Name: pointer to offset 0x0c (the "example.net" in the question)
      0x00, 0x0f,               // Type: MX
      0x00, 0x01,               // Class: IN
      0x00, 0x00, 0x00, 0x3c,   // TTL: 60 seconds
      0x00, 0x09,               // Data length: 11 bytes
      0x00, 0x05,               // Preference: 5
      0x04, 'm', 'a', 'i', 'l', // "mail"
      0xc0, 0x0c                // Domain: pointer to "example.net"
  };

  DnsPacket *packet = parse_dns_packet(dns_response, sizeof(dns_response));

  ck_assert_ptr_nonnull(packet);
  if (packet)
    free_dns_packet(packet);
}
END_TEST

// Add these tests to the test suite
TCase *test__parse_dns_packet(void) {
  TCase *tc_core = tcase_create("parse_dns_packet");

  // queries
  tcase_add_test(tc_core, query_successful_parse_example_com);
  tcase_add_test(tc_core, query_successful_parse_example_org_aaaa);
  tcase_add_test(tc_core, query_successful_parse_example_edu_ptr);

  tcase_add_test(tc_core, query_incorrect_domain_format);
  tcase_add_test(tc_core, query_incorrect_query_type);
  tcase_add_test(tc_core, query_incorrect_flags);
  tcase_add_test(tc_core, query_incorrect_longdomain);

  // responses
  tcase_add_test(tc_core, response_correct_a);
  tcase_add_test(tc_core, response_correct_aaaa);
  tcase_add_test(tc_core, response_correct_mx);
  return tc_core;
}

#include <check.h>
#include "./main.h"

// Test for serializing a valid domain name
START_TEST(test_serialize_valid_domain_name) {
  unsigned char packet[MAX_DNS_PACKET_SIZE];
  const char *domain_name = "1xample.com";

  DomainLabelCacheEntry *cache = NULL;
  int pos = serialize_domain_name(domain_name, packet, 0, &cache);
  free_domain_cache(&cache);

  ck_assert_int_eq(pos, 13);
  ck_assert_int_eq(packet[0], 7);
  ck_assert_mem_eq(packet + 1, "1xample", 7);
  ck_assert_int_eq(packet[8], 3);
  ck_assert_mem_eq(packet + 9, "com", 3);
  ck_assert_int_eq(packet[12], 0);
}
END_TEST

// Test for serializing an empty domain name
START_TEST(test_serialize_empty_domain_name) {
  unsigned char packet[MAX_DNS_PACKET_SIZE];
  const char *domain_name = "";
  DomainLabelCacheEntry *cache = NULL;
  int pos = serialize_domain_name(domain_name, packet, 0, &cache);
  free_domain_cache(&cache);

  ck_assert_int_eq(pos, -1); // Should be error
}
END_TEST

START_TEST(test_serialize_valid_domain_name_with_compress) {
  unsigned char packet[MAX_DNS_PACKET_SIZE];
  const char *first_domain_name = "example.com";
  const char *second_domain_name = "www.example.com";
  const char *third_domain_name = "test.www.example.com";
  const char *forth_domain_name = "mynet.com";
  // const char *fifth_domain_name = "test23.www.example.com.ua";

  DomainLabelCacheEntry *cache = NULL;
  int pos = serialize_domain_name(first_domain_name, packet, 0, &cache);
  pos = serialize_domain_name(second_domain_name, packet, pos, &cache);
  pos = serialize_domain_name(third_domain_name, packet, pos, &cache);
  pos = serialize_domain_name(forth_domain_name, packet, pos, &cache);
  // pos = serialize_domain_name(fifth_domain_name, packet, pos, &cache);
  pos = serialize_domain_name(first_domain_name, packet, pos, &cache);

  free_domain_cache(&cache);

  // clang-format off
  const char packet_should_be[] = {
    0x07, 'e', 'x', 'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o', 'm', 0x00,                   // example.com
    0x03, 'w', 'w', 'w',  0xc0, 0x00, // www > example.com
    0x04, 't', 'e', 's',  't',  0xc0, 0x0D,
    0x05, 'm',  'y', 'n', 'e',  't',  0xc0, 0x08,
    // 0x06, 't', 'e', 's', 't', '2', '3', 0xc0, 0x0D, 0x02, 'u', 'a', 0x00,
    0xc0, 0x00,
  };
  // clang-format on

  ck_assert_int_eq(pos, sizeof(packet_should_be));
  ck_assert_mem_eq(packet_should_be, packet, pos);
}
END_TEST

// Add these tests to the test suite
TCase *test__serialize_and_parse_domain_name(void) {
  TCase *tc_core = tcase_create("serialize_and_parse_domain_name");
  tcase_add_test(tc_core, test_serialize_valid_domain_name);
  tcase_add_test(tc_core, test_serialize_empty_domain_name);
  tcase_add_test(tc_core, test_serialize_valid_domain_name_with_compress);
  return tc_core;
}

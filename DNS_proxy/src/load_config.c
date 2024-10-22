#include "./load_config.h"

const char *default_config_file = "config.ini";

static int handler(void *user, const char *section, const char *name,
                   const char *value) {
  Config *pconfig = (Config *)user;

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  if (MATCH("upstream_dns", "ipaddress")) {
    if (inet_pton(AF_INET, value, &pconfig->upstreamdns_ipaddress.sin_addr) <=
        0)
      return 0;
    pconfig->upstreamdns_ipaddress.sin_family = AF_INET;
  } else if (MATCH("upstream_dns", "port")) {
    pconfig->upstreamdns_ipaddress.sin_port = atoi(value);
  } else if (MATCH("blacklisted", "response")) {
    if (!parse_dns_rcode(value, &pconfig->blacklisted_response)) {
      if (inet_pton(AF_INET, value,
                    &pconfig->blacklisted_ipaddress_response.sin_addr) <= 0)
        return 0;

      pconfig->blacklisted_ipaddress_response.sin_family = AF_INET;
    }
  } else {
    return 0; /* unknown section/name, error */
  }
  return 1;
}

unsigned char load_config(Config *config_out) {
  memset(config_out, 0, sizeof(Config));

  if (ini_parse(default_config_file, handler, config_out) != 0)
    return 0;

  printf("Config successfully loaded\n");
  printf("Upstream destination: %s:%hu\n",
         inet_ntoa(config_out->upstreamdns_ipaddress.sin_addr),
         config_out->upstreamdns_ipaddress.sin_port);
  printf("Blacklisted response: %hhu\n", config_out->blacklisted_response);
  if (config_out->blacklisted_response == 0)
    printf("Blacklisted response ip: %s\n",
           inet_ntoa(config_out->blacklisted_ipaddress_response.sin_addr));

  return 1;
}
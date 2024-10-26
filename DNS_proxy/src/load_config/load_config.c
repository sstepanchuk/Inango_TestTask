#include "./load_config.h"

const char *default_config_file = "config.ini";
const char *default_blackliste_domains_file = "blacklisted.txt";

#define PRINTE_INI_ERROR                                                       \
  printf("Incorrect [%s] -> %s: %s\n", section, name, value)

int handler(void *user, const char *section, const char *name,
            const char *value) {
  Config *pconfig = (Config *)user;

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  if (MATCH("server", "port")) {
    int val = atoi(value);
    if (val < 0 || val > USHRT_MAX) {
      PRINTE_INI_ERROR;
      return 0;
    }
    pconfig->server_port = val;
  } else if (MATCH("upstream_dns", "ipaddress")) {
    if (inet_pton(AF_INET, value, &pconfig->upstreamdns_ipaddress.sin_addr) <=
        0) {
      PRINTE_INI_ERROR;
      return 0;
    }
    pconfig->upstreamdns_ipaddress.sin_family = AF_INET;
  } else if (MATCH("upstream_dns", "port")) {
    int val = atoi(value);
    if (val < 0 || val > USHRT_MAX) {
      PRINTE_INI_ERROR;
      return 0;
    }
    pconfig->upstreamdns_ipaddress.sin_port = htons(val);
  } else if (MATCH("blacklisted", "response")) {
    if (!parse_dns_rcode(value, &pconfig->blacklisted_response)) {
      PRINTE_INI_ERROR;
      return 0;
    }
  } else if (MATCH("blacklisted", "response_ip")) {
    pconfig->blacklisted_ip_response = malloc(sizeof(struct in_addr));
    if (inet_pton(AF_INET, value, pconfig->blacklisted_ip_response) <= 0) {
      PRINTE_INI_ERROR;
      free(pconfig->blacklisted_ip_response);
      pconfig->blacklisted_ip_response = NULL;
      return 0;
    }
  } else if (MATCH("blacklisted", "response_ipv6")) {
    pconfig->blacklisted_ipv6_response = malloc(sizeof(struct in6_addr));
    if (inet_pton(AF_INET6, value, pconfig->blacklisted_ipv6_response) <= 0) {
      PRINTE_INI_ERROR;
      free(pconfig->blacklisted_ipv6_response);
      pconfig->blacklisted_ipv6_response = NULL;
      return 0;
    }
  } else if (MATCH("blacklisted", "file_with_domains")) {
    strcpy(pconfig->blacklist_file, value);
  } else {
    return 0; /* unknown section/name, error */
  }
  return 1;
}

void free_blacklist(BlacklistItem **blacklist) {
  BlacklistItem *tmp, *item;
  HASH_ITER(hh, *blacklist, item, tmp) {
    HASH_DEL(*blacklist, item); /* delete it (users advances to next) */
    free(item);                 /* free it */
  }
}

void free_config(Config *config_out) {
  if (config_out->blacklisted_ip_response)
    free(config_out->blacklisted_ip_response);
  if (config_out->blacklisted_ipv6_response)
    free(config_out->blacklisted_ipv6_response);
  free_blacklist(&config_out->blacklisted_domains_hashmap);
}

// Function to parse domain names from a file and store them in a hash map
unsigned char parse_blacklist_file(const char *filename,
                                   BlacklistItem **blacklist) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    perror("Error opening file");
    return 0;
  }

  char buffer[MAX_DOMAIN_LENGTH + 2]; // Buffer to hold each domain, +2 for
                                      // newline + null terminator
  while (fgets(buffer, sizeof(buffer), file)) {
    // Strip newline character (if present)
    size_t len = strcspn(buffer, "\r\n");
    buffer[len] = '\0';

    // Skip empty lines
    if (len == 0)
      continue;

    // Length check (extra check for any overflow condition)
    if (len > MAX_DOMAIN_LENGTH) {
      fprintf(stderr, "Domain '%s' exceeds max length of 253 characters\n",
              buffer);
      continue;
    }

    // Allocate memory for a new BlacklistItem
    BlacklistItem *item = malloc(sizeof(BlacklistItem));
    if (!item) {
      perror("Memory allocation error");
      fclose(file);
      free_blacklist(blacklist); // Free any previously allocated items
      return 0;
    }

    // Safely copy the domain name to the key
    strncpy(item->key, buffer, MAX_DOMAIN_LENGTH);
    item->key[MAX_DOMAIN_LENGTH - 1] = '\0'; // Ensure null-termination

    // Add the item to the hash map
    HASH_ADD_STR(*blacklist, key, item);
  }

  fclose(file);
  return 1; // Success
}

unsigned char load_config(Config *config_out) {
  memset(config_out, 0, sizeof(Config));
  strcpy(config_out->blacklist_file, default_blackliste_domains_file);
  config_out->server_port = 53;
  if (ini_parse(default_config_file, handler, config_out) != 0)
    return 0;

  if (config_out->upstreamdns_ipaddress.sin_addr.s_addr == 0) {
    printf("[upstream_dns] -> ipaddress is required\n");
    return 0;
  }

  if (config_out->upstreamdns_ipaddress.sin_port == 0) {
    printf("[upstream_dns] -> port is required\n");
    return 0;
  }

  if (config_out->blacklisted_response == DNS_RCODE_NOERROR &&
      (config_out->blacklisted_ip_response == NULL ||
       config_out->blacklisted_ipv6_response == NULL)) {

    printf("if [blacklisted] -> response = NOERROR, need setup\n[blacklisted] "
           "-> ip_response\n[blacklisted] -> ipv6_response\n");
    return 0;
  }

  if (!parse_blacklist_file(config_out->blacklist_file,
                            &config_out->blacklisted_domains_hashmap)) {
    return 0;
  }

  printf("Config successfully loaded\n");
  printf("Upstream destination: %s:%hu\n",
         inet_ntoa(config_out->upstreamdns_ipaddress.sin_addr),
         ntohs(config_out->upstreamdns_ipaddress.sin_port));
  printf("Blacklisted response: %hhu\n", config_out->blacklisted_response);
  if (config_out->blacklisted_response == DNS_RCODE_NOERROR)
    printf("Blacklisted response ip: %s\n",
           inet_ntoa(*config_out->blacklisted_ip_response));

  BlacklistItem *tmp, *domain;
  printf("\n Blacklisted domains: \n");
  HASH_ITER(hh, config_out->blacklisted_domains_hashmap, domain, tmp) {
    printf("%s\n", domain->key);
  }

  return 1;
}
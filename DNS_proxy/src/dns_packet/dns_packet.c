#include "dns_packet.h"

unsigned char parse_dns_rcode(const char *rcode_str, unsigned char *rcode_out) {
  if (!rcode_str || !rcode_out) { // Перевірка вказівників на валідність
    SET_DNS_ERROR("Invalid input pointers");
    return 0;
  }

  if (strcmp(rcode_str, "NOERROR") == 0) {
    *rcode_out = DNS_RCODE_NOERROR;
  } else if (strcmp(rcode_str, "FORMERR") == 0) {
    *rcode_out = DNS_RCODE_FORMERR;
  } else if (strcmp(rcode_str, "SERVFAIL") == 0) {
    *rcode_out = DNS_RCODE_SERVFAIL;
  } else if (strcmp(rcode_str, "NXDOMAIN") == 0) {
    *rcode_out = DNS_RCODE_NXDOMAIN;
  } else if (strcmp(rcode_str, "NOTIMP") == 0) {
    *rcode_out = DNS_RCODE_NOTIMP;
  } else if (strcmp(rcode_str, "REFUSED") == 0) {
    *rcode_out = DNS_RCODE_REFUSED;
  } else if (strcmp(rcode_str, "YXDOMAIN") == 0) {
    *rcode_out = DNS_RCODE_YXDOMAIN;
  } else if (strcmp(rcode_str, "YXRRSET") == 0) {
    *rcode_out = DNS_RCODE_YXRRSET;
  } else if (strcmp(rcode_str, "NXRRSET") == 0) {
    *rcode_out = DNS_RCODE_NXRRSET;
  } else if (strcmp(rcode_str, "NOTAUTH") == 0) {
    *rcode_out = DNS_RCODE_NOTAUTH;
  } else if (strcmp(rcode_str, "NOTZONE") == 0) {
    *rcode_out = DNS_RCODE_NOTZONE;
  } else if (strcmp(rcode_str, "BADVERS") == 0) {
    *rcode_out = DNS_RCODE_BADVERS;
  } else if (strcmp(rcode_str, "BADKEY") == 0) {
    *rcode_out = DNS_RCODE_BADKEY;
  } else if (strcmp(rcode_str, "BADTIME") == 0) {
    *rcode_out = DNS_RCODE_BADTIME;
  } else if (strcmp(rcode_str, "BADMODE") == 0) {
    *rcode_out = DNS_RCODE_BADMODE;
  } else if (strcmp(rcode_str, "BADALG") == 0) {
    *rcode_out = DNS_RCODE_BADALG;
  } else {
    SET_DNS_ERROR("Invalid RCODE: %s",
                  rcode_str); // Додано обробку помилки з деталями
    return 0;
  }

  return 1;
}

char parse_dns_header(const unsigned char *packet, const int packet_size,
                      DnsHeader *header_out) {

  if (!packet || !header_out) { // Перевірка вказівників на валідність
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  if (packet_size < sizeof(DnsHeader)) { // Перевірка розміру пакета
    SET_DNS_ERROR("Packet size is too small");
    return -1;
  }

  const DnsHeader *in_dns_header = (const DnsHeader *)packet;
  memcpy(header_out, packet, sizeof(DnsHeader));

  // Перетворення значень з мережевого порядку байтів у порядок байтів хоста
  header_out->id = ntohs(in_dns_header->id);
  header_out->q_count = ntohs(in_dns_header->q_count);
  header_out->ans_count = ntohs(in_dns_header->ans_count);
  header_out->auth_count = ntohs(in_dns_header->auth_count);
  header_out->add_count = ntohs(in_dns_header->add_count);

  if (!validate_dns_header(header_out, packet_size))
    return -1;

  return 0;
}

// Функція для розбору доменного імені з пакета

int parse_domain_name_recursive(const unsigned char *packet,
                                const int packet_size, int pos,
                                char *parsed_name, int *name_length) {

  if (!packet || !parsed_name || !name_length) { // Перевірка вказівників
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  if (pos >= packet_size) { // Перевірка позиції
    SET_DNS_ERROR("Position out of bounds: %d (packet size: %d)", pos,
                  packet_size);
    return -1;
  }

  int label_length;

  if ((packet[pos] & 0xC0) == 0xC0) { // Стиснення вказівника
    unsigned short offset = ntohs(*(unsigned short *)(packet + pos)) & 0x3FFF;
    if (offset >= packet_size) { // Перевірка зміщення
      SET_DNS_ERROR("Invalid compression offset: %d (packet size: %d)", offset,
                    packet_size);
      return -1;
    }
    if (parse_domain_name_recursive(packet, packet_size, offset, parsed_name,
                                    name_length) < 0) {
      return -1; // Помилка вже оброблена в рекурсивному виклику
    }
    return pos + sizeof(unsigned short);
  }

  label_length = (unsigned char)packet[pos];
  if (label_length == 0) { // Кінець доменного імені
    ++pos;
    return pos;
  }

  if (label_length > MAX_LABEL_LENGTH ||
      *name_length + label_length >= MAX_DOMAIN_LENGTH + 1) {
    SET_DNS_ERROR("Label length exceeds limit: %d (max: %d)", label_length,
                  MAX_LABEL_LENGTH);
    return -1;
  }

  if (!validate_label(packet + pos + 1, label_length)) {
    SET_DNS_ERROR("Invalid label at position %d", pos);
    return -1;
  }

  memcpy(parsed_name + *name_length, packet + pos + 1, label_length);
  *name_length += label_length;
  parsed_name[(*name_length)++] = '.';
  pos += label_length + 1;

  return parse_domain_name_recursive(packet, packet_size, pos, parsed_name,
                                     name_length);
}

int _parse_domain_name(const unsigned char *packet, const int packet_size,
                       int pos, char *parsed_name) {

  if (!packet || !parsed_name) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  if (pos < 0 || pos >= packet_size) {
    SET_DNS_ERROR("Invalid position: %d (packet size: %d)", pos, packet_size);
    return -1;
  }

  int name_length = 0;
  parsed_name[0] = '\0';

  int result = parse_domain_name_recursive(packet, packet_size, pos,
                                           parsed_name, &name_length);

  if (result < 0) {
    return -1;
  }

  if (name_length > 0) {
    parsed_name[name_length - 1] = '\0';
  }

  return result;
}

int parse_domain_name(const unsigned char *packet, const int packet_size,
                      int pos, char **name) {
  char *parsed_name = malloc(MAX_DOMAIN_LENGTH + 1);
  if (!parsed_name) {
    SET_DNS_ERROR("Memory allocation failed");
    return -1;
  }

  int result = _parse_domain_name(packet, packet_size, pos, parsed_name);

  if (result < 0) {
    free(parsed_name);
    return -1;
  }

  *name = parsed_name;
  return result;
}

int parse_dns_queries(const unsigned char *packet, DnsQuery **_queries,
                      const int packet_size, int pos,
                      const unsigned short count) {
  *_queries = malloc(count * sizeof(DnsQuery));
  if (!*_queries) {
    SET_DNS_ERROR("Memory allocation failed");
    return -1;
  }
  DnsQuery *queries = *_queries;

  for (int i = 0; i < count; i++) {
    if ((pos = parse_domain_name(packet, packet_size, pos, &queries[i].name)) <
        0) {
      for (int j = 0; j < i; j++)
        free(queries[j].name);
      free(queries);
      return -1;
    }

    if (pos + 4 > packet_size ||

        !validate_qtype(queries[i].ques.qtype =
                            ntohs(*(unsigned short *)(packet + pos))) ||

        !validate_qclass(queries[i].ques.qclass =
                             ntohs(*(unsigned short *)(packet + pos + 2)))) {
      for (int j = 0; j < i; j++)
        free(queries[j].name);
      free(queries[i].name);
      free(queries);
      return -1;
    }

    pos += 4;
  }
  return pos;
}

int parse_soa_record(const unsigned char *packet, int packet_size, int pos,
                     SOARecord *soa) {
  if (!packet || !soa) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  if (pos >= packet_size) {
    SET_DNS_ERROR("Position out of bounds: %d (packet size: %d)", pos,
                  packet_size);
    return -1;
  }

  pos = _parse_domain_name(packet, packet_size, pos, soa->primary_ns);
  if (pos < 0) {
    return -1;
  }

  pos = _parse_domain_name(packet, packet_size, pos, soa->responsible_email);
  if (pos < 0) {
    return -1;
  }

  if (pos + 20 > packet_size) {
    SET_DNS_ERROR("Not enough data for SOA record");
    return -1;
  }

  soa->serial = ntohl(*(uint32_t *)(packet + pos));
  pos += 4;
  soa->refresh = ntohl(*(uint32_t *)(packet + pos));
  pos += 4;
  soa->retry = ntohl(*(uint32_t *)(packet + pos));
  pos += 4;
  soa->expire = ntohl(*(uint32_t *)(packet + pos));
  pos += 4;
  soa->minimum_ttl = ntohl(*(uint32_t *)(packet + pos));
  pos += 4;

  return pos;
}

int parse_mx_record(const unsigned char *packet, int packet_size, int pos,
                    MXRecord *mx) {

  if (!packet || !mx) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  if (pos >= packet_size) {
    SET_DNS_ERROR("Position out of bounds: %d (packet size: %d)", pos,
                  packet_size);
    return -1;
  }

  if (pos + 2 > packet_size) {
    SET_DNS_ERROR("Not enough data for MX record");
    return -1;
  }

  mx->preference = ntohs(*(uint16_t *)(packet + pos));
  pos += 2;

  pos = _parse_domain_name(packet, packet_size, pos, mx->primary_ns);
  if (pos < 0) {
    return -1;
  }

  return pos;
}

int parse_dns_answers(const unsigned char *packet, DnsAnswer **_answers,
                      const int packet_size, int pos,
                      const unsigned short count) {
  *_answers = malloc(count * sizeof(DnsAnswer));
  if (!*_answers) {
    SET_DNS_ERROR("Memory allocation failed");
    return -1;
  }

  DnsAnswer *answers = *_answers;
  for (int i = 0; i < count; i++) {
    if ((pos = parse_domain_name(packet, packet_size, pos, &answers[i].name)) <
        0) {
      SET_DNS_ERROR("Error parsing domain name in [%d] DNS answer", i);
      for (int j = 0; j < i; j++) {
        free(answers[j].name);
        free(answers[j].data);
      }
      free(answers);
      return -1;
    }

    if (pos + 10 > packet_size ||

        !validate_type(answers[i].type =
                           ntohs(*(unsigned short *)(packet + pos))) ||

        !validate_class(answers[i].class =
                            ntohs(*(unsigned short *)(packet + pos + 2)))) {
      SET_DNS_ERROR("Error parsing type or class in [%d] DNS answer", i);
      for (int j = 0; j < i; j++) {
        free(answers[j].name);
        free(answers[j].data);
      }
      free(answers[i].name);
      free(answers);
      return -1;
    }

    answers[i].ttl = ntohl(*(unsigned int *)(packet + pos + 4));
    unsigned short data_len = ntohs(*(unsigned short *)(packet + pos + 8));
    pos += 10;

    if (data_len > 0) {
      if (pos + data_len > packet_size) {
        SET_DNS_ERROR("Insufficient data for answer record [%d]", i);
        for (int j = 0; j < i; j++) {
          free(answers[j].name);
          free(answers[j].data);
        }
        free(answers[i].name);
        free(answers);
        return -1;
      }

      switch (answers[i].type) {
      case DNS_TYPE_SOA:
        answers[i].data = malloc(sizeof(SOARecord));
        if (!answers[i].data ||
            (pos = parse_soa_record(packet, packet_size, pos,
                                    (SOARecord *)answers[i].data)) < 0) {
          SET_DNS_ERROR("Error parsing SOA record in answer [%d]", i);
          for (int j = 0; j < i; j++) {
            free(answers[j].name);
            free(answers[j].data);
          }
          free(answers[i].name);
          free(answers[i].data);
          free(answers);
          return -1;
        }

        data_len = sizeof(MXRecord);
        break;

      case DNS_TYPE_MX:
        answers[i].data = malloc(sizeof(MXRecord));
        if (!answers[i].data ||
            (pos = parse_mx_record(packet, packet_size, pos,
                                   (MXRecord *)answers[i].data)) < 0) {
          SET_DNS_ERROR("Error parsing MX record in answer [%d]", i);
          for (int j = 0; j < i; j++) {
            free(answers[j].name);
            free(answers[j].data);
          }
          free(answers[i].name);
          free(answers[i].data);
          free(answers);
          return -1;
        }

        data_len = sizeof(MXRecord);
        break;
      case DNS_TYPE_CNAME:
      case DNS_TYPE_NS:
      case DNS_TYPE_PTR:
        if ((pos = parse_domain_name(packet, packet_size, pos,
                                     (char **)&answers[i].data)) < 0) {
          SET_DNS_ERROR("Error parsing CNAME/NS/PTR record in answer [%d]", i);
          for (int j = 0; j < i; j++) {
            free(answers[j].name);
            free(answers[j].data);
          }
          free(answers[i].name);
          free(answers);
          return -1;
        }
        data_len = strlen(answers[i].data);
        break;
      default:
        answers[i].data = malloc(data_len);
        if (!answers[i].data) {
          SET_DNS_ERROR("Memory allocation failed for answer data [%d]", i);
          for (int j = 0; j < i; j++) {
            free(answers[j].name);
            free(answers[j].data);
          }
          free(answers[i].name);
          free(answers);
          return -1;
        }
        memcpy(answers[i].data, packet + pos, data_len);
        pos += data_len;
        break;
      }

    } else
      answers[i].data = NULL;
    answers[i].data_len = data_len;
  }
  return pos;
}

void free_dns_records(DnsAnswer *records, const unsigned short count) {
  if (!records || count == 0)
    return;

  for (int i = 0; i < count; i++) {
    free(records[i].name);
    free(records[i].data);
  }

  free(records);
}

void free_dns_queries(DnsQuery *queries, const unsigned short count) {
  if (!queries || count == 0)
    return;

  for (int i = 0; i < count; i++)
    free(queries[i].name);

  free(queries);
}

DnsPacket *parse_dns_packet(const unsigned char *packet,
                            const int packet_size) {
  if (packet_size < sizeof(DnsHeader)) {
    SET_DNS_ERROR("Packet size is too small");
    return NULL;
  }

  DnsHeader parsed_header;

  if (parse_dns_header(packet, packet_size, &parsed_header) < 0) {
    return NULL;
  }

  DnsPacket *dns_packet = malloc(sizeof(DnsPacket));

  if (!dns_packet) {
    SET_DNS_ERROR("Memory allocation failed");
    return NULL;
  }

  dns_packet->header = parsed_header;
  int pos = sizeof(DnsHeader);

  if (!parsed_header.qr) {
    if ((pos = parse_dns_queries(packet, &dns_packet->queries, packet_size, pos,
                                 dns_packet->header.q_count)) < 0) {
      free(dns_packet);
      return NULL;
    }

    if (dns_packet->header.add_count > 0) {
      if ((pos = parse_dns_answers(packet, &dns_packet->additional, packet_size,
                                   pos, dns_packet->header.add_count)) < 0) {
        free_dns_queries(dns_packet->queries, dns_packet->header.q_count);
        free(dns_packet);
        return NULL;
      }
    }
  } else {
    if (dns_packet->header.q_count > 0) {
      if ((pos = parse_dns_queries(packet, &dns_packet->queries, packet_size,
                                   pos, dns_packet->header.q_count)) < 0) {
        free(dns_packet);
        return NULL;
      }
    }

    if (dns_packet->header.ans_count > 0) {
      if ((pos = parse_dns_answers(packet, &dns_packet->answers, packet_size,
                                   pos, dns_packet->header.ans_count)) < 0) {
        free_dns_queries(dns_packet->queries, dns_packet->header.q_count);
        free(dns_packet);
        return NULL;
      }
    }

    if (dns_packet->header.auth_count > 0) {
      if ((pos =
               parse_dns_answers(packet, &dns_packet->authortative, packet_size,
                                 pos, dns_packet->header.auth_count)) < 0) {
        free_dns_queries(dns_packet->queries, dns_packet->header.q_count);
        free_dns_records(dns_packet->answers, dns_packet->header.ans_count);
        free(dns_packet);
        return NULL;
      }
    }

    if (dns_packet->header.add_count > 0) {
      if ((pos = parse_dns_answers(packet, &dns_packet->additional, packet_size,
                                   pos, dns_packet->header.add_count)) < 0) {
        free_dns_queries(dns_packet->queries, dns_packet->header.q_count);
        free_dns_records(dns_packet->answers, dns_packet->header.ans_count);
        free_dns_records(dns_packet->authortative,
                         dns_packet->header.auth_count);
        free(dns_packet);
        return NULL;
      }
    }
  }

  return dns_packet;
}

// Функція для звільнення пам'яті, виділеної під DnsPacket
void free_dns_packet(DnsPacket *dns_packet) {
  if (!dns_packet)
    return;

  // Звільнення пам'яті для запитів (queries)
  free_dns_queries(dns_packet->queries, dns_packet->header.q_count);

  // Звільнення пам'яті для відповідей (answers)
  free_dns_records(dns_packet->answers, dns_packet->header.ans_count);

  // Звільнення пам'яті для авторитетних записів (authortative)
  free_dns_records(dns_packet->authortative, dns_packet->header.auth_count);

  // Звільнення пам'яті для додаткових записів (additional)
  free_dns_records(dns_packet->additional, dns_packet->header.add_count);

  // Звільнення пам'яті для структури DnsPacket
  free(dns_packet);
}

void print_dns_section(const char *section_name, const DnsAnswer *section,
                       const int count) {
  for (int i = 0; i < count; i++) {
    printf("%s %d: %s, Type: %u, Class: %u, TTL: %u, Data Length: %u\n",
           section_name, i + 1, section[i].name, section[i].type,
           section[i].class, section[i].ttl, section[i].data_len);
    printf("Data: ");
    for (int j = 0; j < section[i].data_len; j++) {
      printf("%02x ", section[i].data[j]);
    }
    printf("\n");
  }
}

void print_dns_packet(const DnsPacket *dns_packet) {
  printf("DNS Packet:\n");
  printf("ID: 0x%x\n",
         dns_packet->header.id); // Виведення ідентифікаційного номера пакета
  printf("QR: %u\n", dns_packet->header.qr); // Виведення флага запиту/відповіді
  printf("Opcode: %u\n",
         dns_packet->header.opcode); // Виведення мети повідомлення
  printf("AA: %u\n",
         dns_packet->header.aa); // Виведення флага авторитетної відповіді
  printf("TC: %u\n",
         dns_packet->header.tc); // Виведення флага обрізаного повідомлення
  printf("RD: %u\n", dns_packet->header.rd); // Виведення флага бажаної рекурсії
  printf("RA: %u\n",
         dns_packet->header.ra); // Виведення флага доступної рекурсії
  printf("Z: %u\n", dns_packet->header.z); // Виведення зарезервованого біта
  printf("RCODE: %u\n", dns_packet->header.rcode); // Виведення коду відповіді
  printf("Queries: %u\n",
         dns_packet->header.q_count); // Виведення кількості запитань
  printf("Answers: %u\n",
         dns_packet->header.ans_count); // Виведення кількості відповідей
  printf("Authority records: %u\n",
         dns_packet->header
             .auth_count); // Виведення кількості авторитетних записів
  printf(
      "Additional records: %u\n",
      dns_packet->header.add_count); // Виведення кількості додаткових записів

  // Виведення інформації про кожне запитання
  for (int i = 0; i < dns_packet->header.q_count; i++) {
    printf("Query %d: %s, Type: %u, Class: %u\n", i + 1,
           dns_packet->queries[i].name, dns_packet->queries[i].ques.qtype,
           dns_packet->queries[i].ques.qclass);
  }

  // Використання єдиної функції для виведення інформації про відповіді,
  // авторитетні і додаткові записи
  print_dns_section("Answer", dns_packet->answers,
                    dns_packet->header.ans_count);
  print_dns_section("Authority", dns_packet->authortative,
                    dns_packet->header.auth_count);
  print_dns_section("Additional", dns_packet->additional,
                    dns_packet->header.add_count);
}

int serialize_domain_name(const char *name, unsigned char *packet, int pos,
                          DomainLabelCacheEntry **domain_cache) {
  if (!name || !packet || !domain_cache) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  const char *ptr = name;
  int name_len = strlen(name);
  DomainLabelCacheEntry *entry;
  int original_pos = pos;
  int label_len = 0;

  while (ptr + 1 < name + name_len) {

    HASH_FIND_STR(*domain_cache, ptr, entry);
    label_len = name_len - (ptr - name);
    if (entry) {
      if (pos + sizeof(unsigned short) >= MAX_DNS_PACKET_SIZE) {
        SET_DNS_ERROR("Packet size exceeded during domain name serialization");
        return -1;
      }

      *(unsigned short *)(packet + pos) = htons(entry->position | 0xC000);
      return pos + sizeof(unsigned short);
    } else {
      const char *dot = strchr(ptr, '.');
      if (dot)
        label_len = dot - ptr;
      if (pos + label_len + 1 >= MAX_DNS_PACKET_SIZE) {
        SET_DNS_ERROR("Packet size exceeded during domain name serialization");
        return -1;
      }
      packet[pos++] = (unsigned char)label_len;
      memcpy(&packet[pos], ptr, label_len);
      pos += label_len;
    }

    HASH_FIND_STR(*domain_cache, ptr, entry);
    if (!entry) {
      entry = malloc(sizeof(DomainLabelCacheEntry));
      if (!entry) {
        SET_DNS_ERROR("Memory allocation failed");
        return -1;
      }

      strcpy(entry->key, ptr);
      entry->position = original_pos;
      HASH_ADD_STR(*domain_cache, key, entry);
    }

    ptr += label_len + 1;
    original_pos = pos;
  }

  packet[pos++] = 0;
  return pos;
}

void free_domain_cache(DomainLabelCacheEntry **domain_cache) {
  DomainLabelCacheEntry *entry, *tmp;
  HASH_ITER(hh, *domain_cache, entry, tmp) {
    HASH_DEL(*domain_cache, entry);
    free(entry);
  }
}

DnsPacket *create_empty_dns_packet_copy(const DnsPacket *packet) {
  DnsPacket *dns_packet_copy = malloc(sizeof(DnsPacket));

  dns_packet_copy->header = packet->header;
  dns_packet_copy->header.q_count = 0;
  dns_packet_copy->header.ans_count = 0;
  dns_packet_copy->header.add_count = 0;
  dns_packet_copy->header.auth_count = 0;

  return dns_packet_copy;
}

int serialize_dns_header(const DnsHeader *header, unsigned char *packet,
                         int pos) {
  if (!header || !packet) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  DnsHeader temp_header = *header;

  temp_header.id = htons(temp_header.id);
  temp_header.q_count = htons(temp_header.q_count);
  temp_header.ans_count = htons(temp_header.ans_count);
  temp_header.auth_count = htons(temp_header.auth_count);
  temp_header.add_count = htons(temp_header.add_count);

  if (pos + sizeof(DnsHeader) > MAX_DNS_PACKET_SIZE) {
    SET_DNS_ERROR("Packet size exceeded during header serialization");
    return -1;
  }
  memcpy(&packet[pos], &temp_header, sizeof(DnsHeader));
  return pos + sizeof(DnsHeader);
}

int serialize_dns_queries(const DnsQuery *queries, unsigned short count,
                          unsigned char *packet, int pos,
                          DomainLabelCacheEntry **domain_cache) {
  if (!queries || !packet || !domain_cache) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  for (int i = 0; i < count; i++) {
    pos = serialize_domain_name(queries[i].name, packet, pos, domain_cache);
    if (pos < 0) {
      return -1;
    }

    if (pos + 4 > MAX_DNS_PACKET_SIZE) {
      SET_DNS_ERROR("Packet size exceeded during query serialization");
      return -1;
    }
    *(unsigned short *)&packet[pos] = htons(queries[i].ques.qtype);
    *(unsigned short *)&packet[pos + 2] = htons(queries[i].ques.qclass);
    pos += 4;
  }

  return pos;
}

int serialize_soa_record(const SOARecord *soa, unsigned char *packet, int pos,
                         DomainLabelCacheEntry **domain_cache) {
  if (!soa || !packet || !domain_cache) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  pos = serialize_domain_name(soa->primary_ns, packet, pos, domain_cache);
  if (pos < 0) {
    return -1;
  }

  pos =
      serialize_domain_name(soa->responsible_email, packet, pos, domain_cache);
  if (pos < 0) {
    return -1;
  }

  if (pos + 20 > MAX_DNS_PACKET_SIZE) {
    SET_DNS_ERROR("Packet size exceeded during SOA record serialization");
    return -1;
  }

  *(uint32_t *)(packet + pos) = htonl(soa->serial);
  pos += 4;
  *(uint32_t *)(packet + pos) = htonl(soa->refresh);
  pos += 4;
  *(uint32_t *)(packet + pos) = htonl(soa->retry);
  pos += 4;
  *(uint32_t *)(packet + pos) = htonl(soa->expire);
  pos += 4;
  *(uint32_t *)(packet + pos) = htonl(soa->minimum_ttl);
  pos += 4;

  return pos;
}

int serialize_mx_record(const MXRecord *mx, unsigned char *packet, int pos,
                        DomainLabelCacheEntry **domain_cache) {
  if (!mx || !packet || !domain_cache) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  if (pos + 2 > MAX_DNS_PACKET_SIZE) {
    SET_DNS_ERROR("Packet size exceeded during MX record serialization");
    return -1;
  }

  *(uint16_t *)(packet + pos) = htons(mx->preference);
  pos += 2;

  pos = serialize_domain_name(mx->primary_ns, packet, pos, domain_cache);
  if (pos < 0) {
    return -1;
  }

  return pos;
}

int serialize_dns_answers(const DnsAnswer *answers, unsigned short count,
                          unsigned char *packet, int pos,
                          DomainLabelCacheEntry **domain_cache) {
  if (!answers || !packet || !domain_cache) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  for (int i = 0; i < count; i++) {
    pos = serialize_domain_name(answers[i].name, packet, pos, domain_cache);
    if (pos < 0) {
      return -1;
    }

    if (pos + 10 > MAX_DNS_PACKET_SIZE) {
      SET_DNS_ERROR("Packet size exceeded during answer serialization");
      return -1;
    }
    *(unsigned short *)&packet[pos] = htons(answers[i].type);
    *(unsigned short *)&packet[pos + 2] = htons(answers[i].class);
    *(unsigned int *)&packet[pos + 4] = htonl(answers[i].ttl);
    *(unsigned short *)&packet[pos + 8] = htons(answers[i].data_len);

    pos += 10;

    if (answers[i].data_len > 0) {
      switch (answers[i].type) {
      case DNS_TYPE_SOA: {
        int data_len_pos = pos - 2;
        pos = serialize_soa_record((const SOARecord *)answers[i].data, packet,
                                   pos, domain_cache);

        if (pos < 0 || data_len_pos + 2 + 10 > MAX_DNS_PACKET_SIZE) {
          return -1;
        }
        *(unsigned short *)&packet[data_len_pos] =
            htons(pos - (data_len_pos + 2));
      } break;
      case DNS_TYPE_MX: {
        int data_len_pos = pos - 2;
        pos = serialize_mx_record((const MXRecord *)answers[i].data, packet,
                                  pos, domain_cache);
        if (pos < 0 || data_len_pos + 2 + 10 > MAX_DNS_PACKET_SIZE) {
          return -1;
        }
        *(unsigned short *)&packet[data_len_pos] =
            htons(pos - (data_len_pos + 2));
      } break;
      case DNS_TYPE_CNAME:
      case DNS_TYPE_NS:
      case DNS_TYPE_PTR: {
        int data_len_pos = pos - 2;
        pos = serialize_domain_name(answers[i].data, packet, pos, domain_cache);
        if (pos < 0 || data_len_pos + 2 + 10 > MAX_DNS_PACKET_SIZE) {
          return -1;
        }
        *(unsigned short *)&packet[data_len_pos] =
            htons(pos - (data_len_pos + 2));
      } break;
      default:
        if (pos + answers[i].data_len > MAX_DNS_PACKET_SIZE) {
          SET_DNS_ERROR(
              "Packet size exceeded during answer data serialization");
          return -1;
        }
        memcpy(&packet[pos], answers[i].data, answers[i].data_len);
        pos += answers[i].data_len;
        break;
      }
    }
  }
  return pos;
}

int serialize_dns_packet(const DnsPacket *dns_packet, unsigned char *packet) {
  if (!dns_packet || !packet) {
    SET_DNS_ERROR("Invalid input pointers");
    return -1;
  }

  int pos = 0;
  DomainLabelCacheEntry *domain_cache = NULL;

  pos = serialize_dns_header(&dns_packet->header, packet, pos);
  if (pos < 0) {
    return -1;
  }

  if (!dns_packet->header.qr) {
    pos = serialize_dns_queries(dns_packet->queries, dns_packet->header.q_count,
                                packet, pos, &domain_cache);
    if (pos < 0) {
      free_domain_cache(&domain_cache);
      return -1;
    }
  } else {
    if (dns_packet->header.q_count > 0) {
      pos =
          serialize_dns_queries(dns_packet->queries, dns_packet->header.q_count,
                                packet, pos, &domain_cache);
      if (pos < 0) {
        free_domain_cache(&domain_cache);
        return -1;
      }
    }

    if (dns_packet->header.ans_count > 0) {
      pos = serialize_dns_answers(dns_packet->answers,
                                  dns_packet->header.ans_count, packet, pos,
                                  &domain_cache);
      if (pos < 0) {
        free_domain_cache(&domain_cache);
        return -1;
      }
    }

    if (dns_packet->header.auth_count > 0) {
      pos = serialize_dns_answers(dns_packet->authortative,
                                  dns_packet->header.auth_count, packet, pos,
                                  &domain_cache);
      if (pos < 0) {
        free_domain_cache(&domain_cache);
        return -1;
      }
    }

    if (dns_packet->header.add_count > 0) {
      pos = serialize_dns_answers(dns_packet->additional,
                                  dns_packet->header.add_count, packet, pos,
                                  &domain_cache);
      if (pos < 0) {
        free_domain_cache(&domain_cache);
        return -1;
      }
    }
  }

  free_domain_cache(&domain_cache);
  return pos;
}

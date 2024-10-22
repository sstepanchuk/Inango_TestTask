#include "dns_packet.h"

unsigned char parse_dns_rcode(const char *rcode_str, unsigned char *rcode_out) {
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
  } else
    return 0;

  return 1;
}

int parse_dns_header(const unsigned char *packet, int packet_size,
                     DnsHeader *header_out) {
  DnsHeader *dns_header = (DnsHeader *)packet;

  // Перетворення значень з мережевого порядку байтів у порядок байтів хоста
  dns_header->id = ntohs(dns_header->id);
  dns_header->q_count = ntohs(dns_header->q_count);
  dns_header->ans_count = ntohs(dns_header->ans_count);
  dns_header->auth_count = ntohs(dns_header->auth_count);
  dns_header->add_count = ntohs(dns_header->add_count);

  if (!validate_dns_header(dns_header, packet_size))
    return -1; // Недійсна кількість

  *header_out = *dns_header;

  return 0;
}

// Функція для розбору доменного імені з пакета
int parse_domain_name(const unsigned char *packet, int packet_size, int pos,
                      char **name) {
  int label_length;
  int name_length = 0;
  int max_length = MAX_DOMAIN_LENGTH + 1; // +1 для нульового байта

  // Виділення початкового буфера для доменного імені
  char *parsed_name = malloc(max_length);
  if (!parsed_name)
    return -1; // Помилка виділення пам'яті

  while (pos < packet_size) {
    label_length = (unsigned char)packet[pos];
    if (label_length == 0)
      break; // Кінець доменного імені

    // Перевірка на недійсну довжину мітки або перевищення загальної довжини
    // імені
    if (label_length > MAX_LABEL_LENGTH ||
        name_length + label_length >= max_length) {
      free(parsed_name);
      return -1; // Недійсна довжина мітки або перевищена загальна довжина
    }

    // Перевірка, чи мітка не починається або не закінчується дефісом
    if (packet[pos + 1] == '-' || packet[pos + label_length] == '-' ||
        !validate_label(packet + pos + 1, label_length)) {
      free(parsed_name);
      return -1; // Мітка не може починатися або закінчуватися дефісом
    }

    // Копіюємо мітку у parsed_name
    memcpy(parsed_name + name_length, packet + pos + 1, label_length);
    name_length += label_length;
    parsed_name[name_length++] = '.'; // Додаємо роздільник між мітками
    pos += label_length + 1;
  }

  // Видалення останньої крапки та завершення доменного імені нульовим байтом
  if (name_length > 0) {
    parsed_name[name_length - 1] = '\0'; // Завершення доменного імені
  } else {
    free(parsed_name);
    return -1; // Недійсна довжина доменного імені
  }

  *name = parsed_name; // Присвоєння розібраного доменного імені
  return (pos + 1); // Повернення позиції після доменного імені
}

// Функція для розбору DNS запитів
int parse_dns_queries(const unsigned char *packet, DnsQuery **_queries,
                      int packet_size, int *pos, unsigned short count) {
  *_queries = malloc(count * sizeof(DnsQuery));
  if (!*_queries) {
    return -1; // Помилка виділення пам'яті
  }
  DnsQuery *queries = *_queries;

  for (int i = 0; i < count; i++) {
    // Розбір доменного імені
    *pos = parse_domain_name(packet, packet_size, *pos, &queries[i].name);
    if (*pos < 0) {
      for (int j = 0; j < i; j++) {
        free(queries[j].name);
      }
      free(queries);
      return -1; // Помилка при розборі доменного імені
    }

    if (*pos + 4 > packet_size ||

        !validate_qtype(queries[i].ques.qtype =
                            ntohs(*(unsigned short *)(packet + *pos))) ||

        !validate_qclass(queries[i].ques.qclass =
                             ntohs(*(unsigned short *)(packet + *pos + 2)))) {
      free(queries[i].name);
      free(queries);
      return -1; // Недійсні дані
    }

    *pos += 4;
  }
  return 0; // Успішно розібрано запити
}

// Функція для розбору DNS відповідей
int parse_dns_answers(const unsigned char *packet, DnsAnswer **_answers,
                      int packet_size, int *pos, unsigned short count) {
  *_answers = malloc(count * sizeof(DnsAnswer));
  if (!*_answers) {
    return -1; // Помилка виділення пам'яті
  }

  DnsAnswer *answers = *_answers;
  for (int i = 0; i < count; i++) {
    // Розбір доменного імені відповіді
    *pos = parse_domain_name(packet, packet_size, *pos, &answers[i].name);
    if (*pos < 0) {
      for (int j = 0; j < i; j++) {
        free(answers[j].name);
        free(answers[j].data);
      }
      free(answers);
      return -1; // Помилка при розборі доменного імені відповіді
    }

    if (*pos + 10 > packet_size ||

        !validate_type(answers[i].type =
                           ntohs(*(unsigned short *)(packet + *pos))) ||

        !validate_class(answers[i].class =
                            ntohs(*(unsigned short *)(packet + *pos + 2)))) {
      for (int j = 0; j < i; j++) {
        free(answers[j].name);
        free(answers[j].data);
      }
      free(answers[i].name);
      free(answers);
      return -1; // Недійсні дані
    }

    answers[i].ttl = ntohl(*(unsigned int *)(packet + *pos + 4));
    unsigned short data_len = ntohs(*(unsigned short *)(packet + *pos + 8));
    *pos += 10;

    // Розбір даних відповіді в залежності від типу
    if (data_len > 0) {
      if (*pos + data_len > packet_size) {
        for (int j = 0; j < i; j++) {
          free(answers[j].name);
          free(answers[j].data);
        }
        free(answers[i].name);
        free(answers);
        return -1; // Недійсні дані
      }
      answers[i].data = malloc(data_len);
      if (!answers[i].data) {
        for (int j = 0; j < i; j++) {
          free(answers[j].name);
          free(answers[j].data);
        }
        free(answers[i].name);
        free(answers);
        return -1; // Помилка виділення пам'яті
      }
      memcpy(answers[i].data, packet + *pos, data_len);
      *pos += data_len;
    } else {
      answers[i].data = NULL; // Якщо немає даних, присвоюємо NULL
    }
  }
  return 0; // Успішно розібрано відповіді
}

void free_dns_records(DnsAnswer *records, unsigned short count) {
  if (!records || count == 0)
    return;

  for (int i = 0; i < count; i++) {
    free(records[i].name); // Звільнення пам'яті для імені домену
    free(records[i].data); // Звільнення пам'яті для даних відповіді
  }

  free(records); // Звільнення пам'яті для масиву записів
}

// Функція для валідації DNS пакета та повернення розібраного DnsPacket
DnsPacket *parse_dns_packet(const unsigned char *packet, int packet_size) {
  if (packet_size < sizeof(DnsHeader))
    return NULL; // Пакет занадто малий, щоб бути дійсним

  DnsHeader parsed_header;

  if (parse_dns_header(packet, packet_size, &parsed_header) < 0) {
    return NULL; // Недійсний заголовок
  }

  DnsPacket *dns_packet = malloc(sizeof(DnsPacket));

  if (!dns_packet)
    return NULL; // Помилка виділення пам'яті

  dns_packet->header = parsed_header;
  int pos = sizeof(DnsHeader); // Початок після заголовка DNS

  if (!parsed_header.qr) {
    if (parse_dns_queries(packet, &dns_packet->queries, packet_size, &pos,
                          dns_packet->header.q_count) < 0) {
      free(dns_packet);
      return NULL;
    }
  } else {
    if (dns_packet->header.q_count > 0) {
      if (parse_dns_queries(packet, &dns_packet->queries, packet_size, &pos,
                            dns_packet->header.q_count) < 0) {
        free(dns_packet);
        return NULL;
      }
    }

    if (dns_packet->header.ans_count > 0) {
      if (parse_dns_answers(packet, &dns_packet->answers, packet_size, &pos,
                            dns_packet->header.ans_count) < 0) {
        free(dns_packet);
        return NULL;
      }
    }

    if (dns_packet->header.auth_count > 0) {
      if (parse_dns_answers(packet, &dns_packet->authortative, packet_size,
                            &pos, dns_packet->header.auth_count) < 0) {
        free_dns_records(dns_packet->answers, dns_packet->header.ans_count);
        free(dns_packet);
        return NULL;
      }
    }

    if (dns_packet->header.add_count > 0) {
      if (parse_dns_answers(packet, &dns_packet->additional, packet_size, &pos,
                            dns_packet->header.add_count) < 0) {
        free_dns_records(dns_packet->additional, dns_packet->header.add_count);
        free(dns_packet);
        return NULL;
      }
    }
  }

  return dns_packet; // Повернення розібраного DNS пакета
}

// Функція для звільнення пам'яті, виділеної під DnsPacket
void free_dns_packet(DnsPacket *dns_packet) {
  if (!dns_packet)
    return;

  // Звільнення пам'яті для запитів (queries)
  if (dns_packet->queries && dns_packet->header.q_count) {
    for (int i = 0; i < dns_packet->header.q_count; i++) {
      free(dns_packet->queries[i].name); // Звільнення пам'яті для імені домену
    }
    free(dns_packet->queries); // Звільнення пам'яті для масиву запитів
  }

  // Звільнення пам'яті для відповідей (answers)
  free_dns_records(dns_packet->answers, dns_packet->header.ans_count);

  // Звільнення пам'яті для авторитетних записів (authortative)
  free_dns_records(dns_packet->authortative, dns_packet->header.auth_count);

  // Звільнення пам'яті для додаткових записів (additional)
  free_dns_records(dns_packet->additional, dns_packet->header.add_count);

  // Звільнення пам'яті для структури DnsPacket
  free(dns_packet);
}

void print_dns_section(const char *section_name, DnsAnswer *section,
                       int count) {
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

void print_dns_packet(DnsPacket *dns_packet) {
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

int serialize_domain_name(const char *name, unsigned char *packet, int pos) {
  if (!name || !packet)
    return -1; // Validate inputs
  const char *ptr = name;

  while (1) {
    // Find the next label (part of the domain name)
    int label_len = 0;

    // Calculate the label length
    while (ptr[label_len] != '\0' && ptr[label_len] != '.') {
      label_len++;
    }

    // Write the label length to the packet
    if (pos >= MAX_DNS_PACKET_SIZE - 1 ||
        pos + label_len + 1 > MAX_DNS_PACKET_SIZE) {
      return -1; // Not enough space in packet
    }
    packet[pos++] = (unsigned char)label_len; // Store label length

    // Write the label itself
    memcpy(&packet[pos], ptr, label_len);
    pos += label_len;

    // Break if reached end of name
    if (ptr[label_len] == '\0') {
      break;
    }

    // Move past the dot
    ptr += label_len + 1; // Move to the next label
  }

  // Null-terminator for domain name
  packet[pos++] = 0; // End of domain name
  return pos;
}

int serialize_dns_header(const DnsHeader *header, unsigned char *packet,
                         int pos) {
  if (!header || !packet)
    return -1; // Validate inputs

  DnsHeader temp_header = *header;

  // Convert values to network byte order
  temp_header.id = htons(temp_header.id);
  temp_header.q_count = htons(temp_header.q_count);
  temp_header.ans_count = htons(temp_header.ans_count);
  temp_header.auth_count = htons(temp_header.auth_count);
  temp_header.add_count = htons(temp_header.add_count);

  // Copy the header to the packet
  if (pos + sizeof(DnsHeader) > MAX_DNS_PACKET_SIZE) {
    return -1; // Not enough space in packet
  }
  memcpy(&packet[pos], &temp_header, sizeof(DnsHeader));
  return pos + sizeof(DnsHeader);
}

int serialize_dns_queries(const DnsQuery *queries, unsigned short count,
                          unsigned char *packet, int pos) {
  if (!queries || !packet)
    return -1; // Validate inputs
  for (int i = 0; i < count; i++) {
    // Serialize the domain name
    pos = serialize_domain_name(queries[i].name, packet, pos);
    if (pos < 0) {
      return -1; // Error during serialization
    }

    // Serialize the query type and class
    if (pos + 4 > MAX_DNS_PACKET_SIZE) {
      return -1; // Not enough space in packet
    }
    *(unsigned short *)&packet[pos] = htons(queries[i].ques.qtype);
    *(unsigned short *)&packet[pos + 2] = htons(queries[i].ques.qclass);
    pos += 4;
  }
  return pos;
}

int serialize_dns_answers(const DnsAnswer *answers, unsigned short count,
                          unsigned char *packet, int pos) {
  if (!answers || !packet)
    return -1; // Validate inputs
  for (int i = 0; i < count; i++) {
    // Serialize the domain name
    pos = serialize_domain_name(answers[i].name, packet, pos);
    if (pos < 0) {
      return -1; // Error during serialization
    }

    // Serialize type, class, TTL, and data length
    if (pos + 10 > MAX_DNS_PACKET_SIZE) {
      return -1; // Not enough space in packet
    }
    *(unsigned short *)&packet[pos] = htons(answers[i].type);
    *(unsigned short *)&packet[pos + 2] = htons(answers[i].class);
    *(unsigned int *)&packet[pos + 4] = htonl(answers[i].ttl);
    *(unsigned short *)&packet[pos + 8] =
        htons(answers[i].data ? answers[i].data_len : 0);
    pos += 10;

    // Copy the answer data
    if (answers[i].data && answers[i].data_len > 0) {
      if (pos + answers[i].data_len > MAX_DNS_PACKET_SIZE) {
        return -1; // Not enough space in packet
      }
      memcpy(&packet[pos], answers[i].data, answers[i].data_len);
      pos += answers[i].data_len;
    }
  }
  return pos;
}

int serialize_dns_packet(const DnsPacket *dns_packet, unsigned char *packet) {
  if (!dns_packet || !packet)
    return -1; // Validate inputs
  int pos = 0;

  // Serialize the DNS header
  pos = serialize_dns_header(&dns_packet->header, packet, pos);
  if (pos < 0) {
    return -1; // Error during serialization
  }

  // Serialize queries if it's a query packet
  if (!dns_packet->header.qr) {
    pos = serialize_dns_queries(dns_packet->queries, dns_packet->header.q_count,
                                packet, pos);
    if (pos < 0) {
      return -1; // Error during serialization
    }
  } else {
    if (dns_packet->header.q_count > 0) {
      pos = serialize_dns_queries(dns_packet->queries,
                                  dns_packet->header.q_count, packet, pos);
      if (pos < 0) {
        return -1; // Error during serialization
      }
    }

    if (dns_packet->header.ans_count > 0) {
      pos = serialize_dns_answers(dns_packet->answers,
                                  dns_packet->header.ans_count, packet, pos);
      if (pos < 0) {
        return -1; // Error during serialization
      }
    }

    if (dns_packet->header.auth_count > 0) {
      pos = serialize_dns_answers(dns_packet->authortative,
                                  dns_packet->header.auth_count, packet, pos);
      if (pos < 0) {
        return -1; // Error during serialization
      }
    }

    if (dns_packet->header.add_count > 0) {
      pos = serialize_dns_answers(dns_packet->additional,
                                  dns_packet->header.add_count, packet, pos);
      if (pos < 0) {
        return -1; // Error during serialization
      }
    }
  }

  return pos; // Return the final position (size of the packet)
}

#include "dns_packet.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Функція для розбору доменного імені з пакета
int parse_domain_name(const unsigned char *packet, int packet_size, int pos,
                      unsigned char **name) {
  int label_length, name_length = 0;
  char *parsed_name =
      malloc(MAX_DNS_PACKET_SIZE - sizeof(DnsHeader) -
             sizeof(DnsQuestion)); // Виділення пам'яті для доменного імені

  if (!parsed_name)
    return -1; // Помилка виділення пам'яті

  while (pos < packet_size &&
         (label_length = (unsigned char)packet[pos]) != 0) {
    if (label_length > 63 || pos + label_length + 1 >= packet_size) {
      free(parsed_name);
      return -1; // Недійсна довжина мітки або вихід за межі
    }
    memcpy(parsed_name + name_length, packet + pos + 1, label_length);
    name_length += label_length;
    parsed_name[name_length++] = '.'; // Додавання роздільника між мітками
    pos += label_length + 1;
  }

  parsed_name[name_length - 1] =
      '\0'; // Завершення доменного імені нульовим байтом
  *name = (unsigned char *)parsed_name;

  return (pos + 1); // Повернення позиції після доменного імені
}

// Функція для валідації DNS пакета та повернення розібраного DnsPacket
DnsPacket *parse_dns_packet(const unsigned char *packet, int packet_size) {
  if (packet_size < sizeof(DnsHeader))
    return NULL; // Пакет занадто малий, щоб бути дійсним

  DnsHeader *dns_header = (DnsHeader *)packet;

  // Перетворення значень з мережевого порядку байтів у порядок байтів хоста
  dns_header->id = ntohs(dns_header->id);
  dns_header->q_count = ntohs(dns_header->q_count);
  dns_header->ans_count = ntohs(dns_header->ans_count);
  dns_header->auth_count = ntohs(dns_header->auth_count);
  dns_header->add_count = ntohs(dns_header->add_count);

  // Перевірка значень заголовка перед виділенням пам'яті
  if (dns_header->q_count == 0 ||
      dns_header->q_count >
          ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsQuestion)))
    return NULL; // Недійсна кількість запитів

  DnsPacket *dns_packet = malloc(sizeof(DnsPacket));

  if (!dns_packet)
    return NULL; // Помилка виділення пам'яті

  dns_packet->header = *dns_header;
  dns_packet->queries = malloc(dns_header->q_count * sizeof(DnsQuery));

  if (!dns_packet->queries) {
    free(dns_packet);
    return NULL; // Помилка виділення пам'яті
  }

  int pos = sizeof(DnsHeader); // Початок після заголовка DNS
  for (int i = 0; i < dns_header->q_count; i++) {
    // Розбір доменного імені
    pos = parse_domain_name(packet, packet_size, pos,
                            &dns_packet->queries[i].name);
    if (pos < 0) {
      // Звільнення виділеної пам'яті у разі помилки
      for (int j = 0; j < i; j++) {
        free(dns_packet->queries[j].name);
      }
      free(dns_packet->queries);
      free(dns_packet);
      return NULL;
    }

    // Розбір типу та класу запитання
    if (pos + 4 > packet_size) {
      free(dns_packet->queries[i].name);
      free(dns_packet->queries);
      free(dns_packet);
      return NULL; // Недійсні дані
    }
    dns_packet->queries[i].ques.qtype =
        ntohs(*(unsigned short *)(packet + pos));
    dns_packet->queries[i].ques.qclass =
        ntohs(*(unsigned short *)(packet + pos + 2));
    pos += 4;
  }

  return dns_packet; // Повернення розібраного DNS пакета
}

// Функція для звільнення пам'яті, виділеної під DnsPacket
void free_dns_packet(DnsPacket *dns_packet) {
  if (dns_packet) {
    for (int i = 0; i < dns_packet->header.q_count; i++) {
      free(dns_packet->queries[i].name);
    }
    free(dns_packet->queries);
    free(dns_packet);
  }
}

// Допоміжна функція для виведення на екран розібраного DNS пакета
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
  printf("Questions: %u\n",
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
}

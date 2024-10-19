#ifndef DNS_PACKET_H 
#define DNS_Packet_H

// Максимальний розмір DNS пакета (без EDNS)
#define MAX_DNS_PACKET_SIZE 512

typedef struct {
  unsigned short id; // Ідентифікаційний номер

  // Ці флаги є частиною першого байта (використовуються як для запитів, так і для відповідей)
  unsigned char rd : 1;     // Рекурсія бажана (використовується в запиті)
  unsigned char tc : 1;     // Обрізане повідомлення (використовується у відповіді)
  unsigned char aa : 1;     // Авторитетна відповідь (використовується у відповіді)
  unsigned char opcode : 4; // Мета повідомлення (використовується в запиті)
  unsigned char qr : 1;     // Флаг запиту/відповіді (0 = запит, 1 = відповідь)

  // Ці флаги є частиною другого байта (в основному використовуються у відповіді)
  unsigned char rcode : 4; // Код відповіді (використовується у відповіді)
  unsigned char cd : 1;    // Перевірка вимкнена (використовується в запиті)
  unsigned char ad : 1;    // Аутентифіковані дані (використовуються у відповіді)
  unsigned char z : 1;     // Зарезервовано, має бути нульовим (обидва)
  unsigned char ra : 1;    // Рекурсія доступна (використовується у відповіді)

  unsigned short q_count;   // Кількість запитань (як запитів, так і відповідей)
  unsigned short ans_count; // Кількість відповідей (використовується у відповіді)
  unsigned short
      auth_count; // Кількість авторитетних записів (використовується у відповіді)
  unsigned short add_count; // Кількість додаткових записів (використовується у відповіді)
} DnsHeader;

typedef struct {
  unsigned short qtype;  // Тип запиту
  unsigned short qclass; // Клас запиту
} DnsQuestion;

typedef struct {
  unsigned char *name; // Вказівник на доменне ім'я (розібране з пакета)
  DnsQuestion ques;    // Тип та клас запитання
} DnsQuery;

typedef struct {
  DnsHeader header;    // Заголовок DNS
  DnsQuery *queries;   // Запитання
} DnsPacket;

int parse_domain_name(const unsigned char *packet, int packet_size, int pos,
                      unsigned char **name);
DnsPacket *parse_dns_packet(const unsigned char *packet, int packet_size);
void free_dns_packet(DnsPacket *dns_packet);
void print_dns_packet(DnsPacket *dns_packet);

#endif
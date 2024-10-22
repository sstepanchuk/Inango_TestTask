#ifndef DNS_DEFS_H
#define DNS_DEFS_H

#define MAX_DNS_PACKET_SIZE 512
#define MAX_DOMAIN_LENGTH 253
#define MAX_LABEL_LENGTH 63

// TYPE values used in DNS resource records (RFC 1035 and beyond)
#define DNS_TYPE_A 0x0001     // Host address (IPv4)
#define DNS_TYPE_NS 0x0002    // Authoritative name server
#define DNS_TYPE_MD 0x0003    // Mail destination (obsolete)
#define DNS_TYPE_MF 0x0004    // Mail forwarder (obsolete)
#define DNS_TYPE_CNAME 0x0005 // Canonical name for an alias
#define DNS_TYPE_SOA 0x0006   // Start of a zone of authority
#define DNS_TYPE_MB 0x0007    // Mailbox domain name (experimental)
#define DNS_TYPE_MG 0x0008    // Mail group member (experimental)
#define DNS_TYPE_MR 0x0009    // Mail rename domain name (experimental)
#define DNS_TYPE_NULL 0x000A  // Null RR (experimental)
#define DNS_TYPE_WKS 0x000B   // Well-known service description
#define DNS_TYPE_PTR 0x000C   // Domain name pointer (reverse DNS)
#define DNS_TYPE_HINFO 0x000D // Host information
#define DNS_TYPE_MINFO 0x000E // Mailbox or mail list information
#define DNS_TYPE_MX 0x000F    // Mail exchange
#define DNS_TYPE_TXT 0x0010   // Text strings
#define DNS_TYPE_AAAA 0x001C  // IPv6 address
#define DNS_TYPE_SRV 0x0021   // Service locator

// QTYPE values used only in DNS queries (RFC 1035 and beyond)
#define DNS_QTYPE_AXFR 0x00FC  // Transfer of entire zone
#define DNS_QTYPE_MAILB 0x00FD // Mailbox-related records (obsolete)
#define DNS_QTYPE_MAILA 0x00FE // Mail agent (obsolete)
#define DNS_QTYPE_ANY 0x00FF   // Request for any resource record type

// CLASS values used in DNS resource records (RFC 1035)
#define DNS_CLASS_IN 0x0001 // Internet class
#define DNS_CLASS_CS 0x0002 // CSNET class (obsolete)
#define DNS_CLASS_CH 0x0003 // CHAOS class
#define DNS_CLASS_HS 0x0004 // Hesiod class

// QCLASS values used only in DNS queries (RFC 1035)
#define DNS_QCLASS_ANY 0x00FF // Request for any class

// DNS rcode header opcodes
#define DNS_RCODE_NOERROR 0x0  // No Error
#define DNS_RCODE_FORMERR 0x1  // Format Error
#define DNS_RCODE_SERVFAIL 0x2 // Server Failure
#define DNS_RCODE_NXDOMAIN 0x3 // Non-Existent Domain
#define DNS_RCODE_NOTIMP 0x4   // Not Implemented
#define DNS_RCODE_REFUSED 0x5  // Query Refused
#define DNS_RCODE_YXDOMAIN 0x6 // Name Exists when it should not
#define DNS_RCODE_YXRRSET 0x7  // RR Set Exists when it should not
#define DNS_RCODE_NXRRSET 0x8  // RR Set Does Not Exist
#define DNS_RCODE_NOTAUTH 0x9  // Not Authorized
#define DNS_RCODE_NOTZONE 0xA  // Not in Zone
#define DNS_RCODE_BADVERS 0xB  // Bad OPT Version / DNSSEC-related error
#define DNS_RCODE_BADKEY 0xC   // Bad Key (DNSSEC)
#define DNS_RCODE_BADTIME 0xD  // Bad Timestamp (DNSSEC)
#define DNS_RCODE_BADMODE 0xE  // Bad Mode
#define DNS_RCODE_BADALG 0xF   // Bad Algorithm

// DNS packet header opcodes
#define DNS_OPCODE_QUERY 0x0  // Standard query
#define DNS_OPCODE_IQUERY 0x1 // Inverse query (deprecated)
#define DNS_OPCODE_STATUS 0x2 // Server status request (deprecated)
#define DNS_OPCODE_NOTIFY 0x3 // Notify message (used in DNS zone transfers)
#define DNS_OPCODE_UPDATE 0x4 // Dynamic update request

typedef struct {
  unsigned short id; // Ідентифікаційний номер

  // Ці флаги є частиною першого байта (використовуються як для запитів, так і
  // для відповідей)
  unsigned char rd : 1; // Рекурсія бажана (використовується в запиті)
  unsigned char tc : 1; // Обрізане повідомлення (використовується у відповіді)
  unsigned char aa : 1; // Авторитетна відповідь (використовується у відповіді)
  unsigned char opcode : 4; // Мета повідомлення (використовується в запиті)
  unsigned char qr : 1; // Флаг запиту/відповіді (0 = запит, 1 = відповідь)

  // Ці флаги є частиною другого байта (в основному використовуються у
  // відповіді)
  unsigned char rcode : 4; // Код відповіді (використовується у відповіді)
  unsigned char cd : 1; // Перевірка вимкнена (використовується в запиті)
  unsigned char ad : 1; // Аутентифіковані дані (використовуються у відповіді)
  unsigned char z : 1; // Зарезервовано, має бути нульовим (обидва)
  unsigned char ra : 1; // Рекурсія доступна (використовується у відповіді)

  unsigned short q_count; // Кількість запитань (як запитів, так і відповідей)
  unsigned short
      ans_count; // Кількість відповідей (використовується у відповіді)
  unsigned short auth_count; // Кількість авторитетних записів (використовується
                             // у відповіді)
  unsigned short
      add_count; // Кількість додаткових записів (використовується у відповіді)
} DnsHeader;

typedef struct {
  unsigned short qtype;  // Тип запиту
  unsigned short qclass; // Клас запиту
} DnsQuestion;

typedef struct {
  char *name; // Вказівник на доменне ім'я (розібране з пакета)
  DnsQuestion ques; // Тип та клас запитання
} DnsQuery;

typedef struct {
  char *name;              // Доменне ім'я відповіді
  unsigned short type;     // Тип запису (A, AAAA, CNAME тощо)
  unsigned short class;    // Клас запису (IN, CH, HS тощо)
  unsigned int ttl;        // Час життя (Time to Live)
  unsigned short data_len; // Довжина даних відповіді
  unsigned char *data; // Дані відповіді (можуть бути IP адресою, CNAME тощо)
} DnsAnswer;
typedef DnsAnswer DnsAuthortative;
typedef DnsAnswer DnsAdditional;

typedef struct {
  DnsHeader header;  // Заголовок DNS
  DnsQuery *queries; // Запитання
  DnsAnswer *answers;
  DnsAuthortative *authortative;
  DnsAdditional *additional;
} DnsPacket;

#endif
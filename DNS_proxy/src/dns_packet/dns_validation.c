#include "dns_packet.h"

int validate_dns_header(DnsHeader *dns_header, int packet_size) {
  // Перевірка загального розміру пакета
  if (packet_size < sizeof(DnsHeader)) {
    return 0; // Пакет занадто малий
  }

  // Перевірка зарезервованого біта "z"
  if (dns_header->z != 0) {
    return 0; // Зарезервований біт повинен бути нульовим
  }

  // Перевірка флагів (qr, opcode, rcode, тощо)
  if (dns_header->opcode > 15 || dns_header->rcode > 15) {
    return 0; // Невірний код операції або код відповіді
  }

  // Перевірка для DNS відповіді
  if (dns_header->qr) {
    if (dns_header->q_count > 0) {
      return 0; // Відповідь не повинна містити запитів
    }

    // Перевірка на коректність кількості відповідей та додаткових записів
    if (dns_header->ans_count + dns_header->add_count + dns_header->auth_count >
        ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsAnswer))) {
      return 0; // Загальна кількість записів перевищує максимальний розмір
                // пакету
    }
  }
  // Перевірка для DNS запиту
  else {
    if (dns_header->ans_count > 0 || dns_header->auth_count > 0) {
      return 0; // Запит не повинен містити відповідей або авторитетних записів
    }

    if (dns_header->q_count == 0) {
      return 0; // Запит повинен містити хоча б один запит
    }

    if (dns_header->q_count >
        ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsQuestion))) {
      return 0; // Кількість запитів перевищує допустимий розмір пакета
    }
  }

  // Перевірка на рекурсію та обрізане повідомлення
  if (dns_header->tc && dns_header->q_count == 0) {
    return 0; // Обрізане повідомлення не повинно містити 0 запитів
  }

  return 1; // Заголовок валідний
}

int validate_type(unsigned short type) {
  // Validate type (should be either TYPE or QTYPE)
  switch (type) {
  case TYPE_A:
  case TYPE_NS:
  case TYPE_MD:
  case TYPE_MF:
  case TYPE_CNAME:
  case TYPE_SOA:
  case TYPE_MB:
  case TYPE_MG:
  case TYPE_MR:
  case TYPE_NULL:
  case TYPE_WKS:
  case TYPE_PTR:
  case TYPE_HINFO:
  case TYPE_MINFO:
  case TYPE_MX:
  case TYPE_TXT:
  case TYPE_AAAA:
  case TYPE_SRV:
    break; // Valid type
  default:
    return 0; // Invalid type
  }

  return 1; // Both type and class are valid
}

int validate_class(unsigned short class) {
  // Validate class
  switch (class) {
  case CLASS_IN:
  case CLASS_CS:
  case CLASS_CH:
  case CLASS_HS:
    return 1; // Valid class
  default:
    return 0; // Invalid class
  }

  return 1; // Both type and class are valid
}

int validate_qtype(unsigned short qtype) {
  if (validate_type(qtype))
    return 1;

  switch (qtype) {
  case QTYPE_AXFR:
  case QTYPE_MAILB:
  case QTYPE_MAILA:
  case QTYPE_ANY:
    return 1;
  default:
    return 0; // Invalid qtype
  }
}

int validate_qclass(unsigned short qclass) {
  if (validate_class(qclass))
    return 1;

  switch (qclass) {
  case QCLASS_ANY:
    return 1;
  default:
    return 0; // Invalid qtype
  }
}
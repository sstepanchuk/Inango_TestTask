#include "dns_validation.h"

unsigned char validate_dns_header(const DnsHeader *dns_header,
                                  int packet_size) {
  if (!dns_header) {
    SET_DNS_ERROR("Invalid input pointer");
    return 0;
  }

  if (packet_size < sizeof(DnsHeader)) {
    SET_DNS_ERROR("Packet size is too small");
    return 0;
  }

  if (dns_header->z != 0) {
    SET_DNS_ERROR("Reserved field 'z' is not zero");
    return 0;
  }

  if (dns_header->opcode > DNS_OPCODE_UPDATE ||
      dns_header->rcode > DNS_RCODE_BADALG) {
    SET_DNS_ERROR("Invalid opcode or rcode");
    return 0;
  }

  if (dns_header->qr) {
    if (dns_header->ans_count + dns_header->add_count + dns_header->auth_count +
            dns_header->q_count >
        ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsAnswer)) +
            ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsQuestion))) {
      SET_DNS_ERROR("Too many records for the packet size");
      return 0;
    }
  }

  else if (dns_header->tc || dns_header->ans_count > 0 ||
           dns_header->auth_count > 0 || dns_header->q_count == 0 ||
           dns_header->q_count + dns_header->add_count >
               ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsAnswer)) +
                   ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) /
                    sizeof(DnsQuestion))) {
    SET_DNS_ERROR("Invalid header field combination for a query");
    return 0;
  }

  return 1;
}

static unsigned char _validate_type(const unsigned short type) {
  switch (type) {
  case DNS_TYPE_A:
  case DNS_TYPE_NS:
  case DNS_TYPE_MD:
  case DNS_TYPE_MF:
  case DNS_TYPE_CNAME:
  case DNS_TYPE_SOA:
  case DNS_TYPE_MB:
  case DNS_TYPE_MG:
  case DNS_TYPE_MR:
  case DNS_TYPE_NULL:
  case DNS_TYPE_WKS:
  case DNS_TYPE_PTR:
  case DNS_TYPE_HINFO:
  case DNS_TYPE_MINFO:
  case DNS_TYPE_MX:
  case DNS_TYPE_TXT:
  case DNS_TYPE_AAAA:
  case DNS_TYPE_SRV:
  case DNS_TYPE_RRSIG:
  case DNS_TYPE_NSEC:
  case DNS_TYPE_CAA:
    return 1;
  default:
    return 0;
  }
}

static unsigned char _validate_class(const unsigned short class) {
  switch (class) {
  case DNS_CLASS_IN:
  case DNS_CLASS_CS:
  case DNS_CLASS_CH:
  case DNS_CLASS_HS:
    return 1;
  default:
    return 0;
  }
}

unsigned char validate_qtype(const unsigned short qtype) {
  if (_validate_type(qtype))
    return 1;

  switch (qtype) {
  case DNS_QTYPE_AXFR:
  case DNS_QTYPE_MAILB:
  case DNS_QTYPE_MAILA:
  case DNS_QTYPE_ANY:
    return 1;
  default:
    SET_DNS_ERROR("Invalid qtype: %hu", qtype);
    return 0;
  }
}

unsigned char validate_qclass(const unsigned short qclass) {
  if (_validate_class(qclass))
    return 1;

  switch (qclass) {
  case DNS_QCLASS_ANY:
    return 1;
  default:
    SET_DNS_ERROR("Invalid qclass: %hu", qclass);
    return 0;
  }
}

unsigned char validate_type(const unsigned short type) {
  if (_validate_type(type))
    return 1;
  else {
    SET_DNS_ERROR("Invalid type: %hu", type);
    return 0;
  }
}

unsigned char validate_class(const unsigned short class) {
  if (_validate_class(class))
    return 1;
  else {
    SET_DNS_ERROR("Invalid class: %hu", class);
    return 0;
  }
}

unsigned char validate_label(const unsigned char *packet_with_pos,
                             const int label_length) {
  if (!packet_with_pos) {
    SET_DNS_ERROR("Invalid input pointer");
    return 0;
  }

  if (!label_length || packet_with_pos[0] == '-' ||
      packet_with_pos[label_length - 1] == '-') {
    SET_DNS_ERROR("Invalid label: starts or ends with a hyphen");
    return 0;
  }

  for (int i = 0; i < label_length; i++) {
    char ch = packet_with_pos[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
          (ch >= '0' && ch <= '9') || (ch == '-') || (ch == '@'))) {
      SET_DNS_ERROR("Invalid label: contains invalid character '%c'", ch);
      return 0;
    }
  }
  return 1;
}
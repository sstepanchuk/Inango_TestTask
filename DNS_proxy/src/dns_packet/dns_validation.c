#include "dns_packet.h"

int validate_dns_header(DnsHeader *dns_header, int packet_size) {

  if (packet_size < sizeof(DnsHeader)) {
    return 0;
  }

  if (dns_header->z != 0) {
    return 0;
  }

  if (dns_header->opcode > 15 || dns_header->rcode > 15) {
    return 0;
  }

  if (dns_header->qr) {
    if (dns_header->q_count > 0) {
      return 0;
    }

    if (dns_header->ans_count + dns_header->add_count + dns_header->auth_count >
        ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsAnswer))) {
      return 0;
    }
  }

  else {
    if (dns_header->ans_count > 0 || dns_header->auth_count > 0) {
      return 0;
    }

    if (dns_header->q_count == 0) {
      return 0;
    }

    if (dns_header->q_count >
        ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsQuestion))) {
      return 0;
    }
  }

  if (dns_header->tc && dns_header->q_count == 0) {
    return 0;
  }

  return 1;
}

int validate_type(unsigned short type) {

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
    break;
  default:
    return 0;
  }

  return 1;
}

int validate_class(unsigned short class) {

  switch (class) {
  case CLASS_IN:
  case CLASS_CS:
  case CLASS_CH:
  case CLASS_HS:
    return 1;
  default:
    return 0;
  }

  return 1;
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
    return 0;
  }
}

int validate_qclass(unsigned short qclass) {
  if (validate_class(qclass))
    return 1;

  switch (qclass) {
  case QCLASS_ANY:
    return 1;
  default:
    return 0;
  }
}

int is_valid_label(const unsigned char *packet_with_pos, int label_length) {
  if (!label_length || packet_with_pos[0] == '-' ||
      packet_with_pos[label_length - 1] == '-') {
    return 0;
  }

  for (int i = 0; i < label_length; i++) {
    char ch = packet_with_pos[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
          (ch >= '0' && ch <= '9') || (ch == '-'))) {
      return 0;
    }
  }
  return 1;
}
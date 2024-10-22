#include "dns_packet.h"

int validate_dns_header(DnsHeader *dns_header, int packet_size) {

  if (packet_size < sizeof(DnsHeader)) {
    return 0;
  }

  if (dns_header->z != 0) {
    return 0;
  }

  if (dns_header->opcode > DNS_OPCODE_UPDATE ||
      dns_header->rcode > DNS_RCODE_BADALG) {
    return 0;
  }

  if (dns_header->qr) {
    if (dns_header->ans_count + dns_header->add_count + dns_header->auth_count +
            dns_header->q_count >
        ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsAnswer)) +
            ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) / sizeof(DnsQuestion))) {
      return 0;
    }
  }

  else if (dns_header->tc || dns_header->ans_count > 0 ||
           dns_header->auth_count > 0 || dns_header->q_count == 0 ||
           dns_header->q_count > ((MAX_DNS_PACKET_SIZE - sizeof(DnsHeader)) /
                                  sizeof(DnsQuestion))) {
    return 0;
  }

  return 1;
}

int validate_type(unsigned short type) {

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
    break;
  default:
    return 0;
  }

  return 1;
}

int validate_class(unsigned short class) {

  switch (class) {
  case DNS_CLASS_IN:
  case DNS_CLASS_CS:
  case DNS_CLASS_CH:
  case DNS_CLASS_HS:
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
  case DNS_QTYPE_AXFR:
  case DNS_QTYPE_MAILB:
  case DNS_QTYPE_MAILA:
  case DNS_QTYPE_ANY:
    return 1;
  default:
    return 0;
  }
}

int validate_qclass(unsigned short qclass) {
  if (validate_class(qclass))
    return 1;

  switch (qclass) {
  case DNS_QCLASS_ANY:
    return 1;
  default:
    return 0;
  }
}

int validate_label(const unsigned char *packet_with_pos, int label_length) {
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
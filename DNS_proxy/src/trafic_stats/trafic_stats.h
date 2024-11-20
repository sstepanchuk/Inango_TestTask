#ifndef TRAFIC_STATS_H
#define TRAFIC_STATS_H

#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include "thpool.h"
#include "dns_packet_list.h"

#define INTERVAL 1 // Інтервал вимірювання трафіку (в секундах)
#define NS_IN_SECOND 1000000000
#define NS_IN_MKS 1000
#define MKS_IN_SECOND 1000000

typedef struct {
  unsigned long long total_rx_bytes; // Загальна кількість отриманих байтів
  unsigned long long total_tx_bytes; // Загальна кількість відправлених байтів
  unsigned long long prev_rx_bytes; // Попередня кількість отриманих байтів
  unsigned long long prev_tx_bytes; // Попередня кількість відправлених байтів
  unsigned long long total_packets;
  time_t start_time; // Час початку вимірювання
  pthread_mutex_t lock;
  struct timespec prev_time;
} TrafficStats;

void calculate_and_print_traffic_speed(TrafficStats *stats,
                                       threadpool incomming_pool,
                                       threadpool outgoing_pool);

#endif
#ifndef TRAFIC_STATS_H
#define TRAFIC_STATS_H

#include <pthread.h>
#include <stdio.h>
#include <time.h>

#define INTERVAL 1 // Інтервал вимірювання трафіку (в секундах)

typedef struct {
  unsigned long long total_rx_bytes; // Загальна кількість отриманих байтів
  unsigned long long total_tx_bytes; // Загальна кількість відправлених байтів
  unsigned long long prev_rx_bytes; // Попередня кількість отриманих байтів
  unsigned long long prev_tx_bytes; // Попередня кількість відправлених байтів
  time_t start_time; // Час початку вимірювання
  pthread_mutex_t lock;
} TrafficStats;

void calculate_and_print_traffic_speed(TrafficStats *stats);

#endif
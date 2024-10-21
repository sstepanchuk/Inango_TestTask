#include "trafic_stats.h"

/*void calculate_and_print_traffic_speed(TrafficStats *stats) {
  pthread_mutex_lock(&stats->lock);

  unsigned long long rx_speed =
      (stats->total_rx_bytes - stats->prev_rx_bytes) / INTERVAL;
  unsigned long long tx_speed =
      (stats->total_tx_bytes - stats->prev_tx_bytes) / INTERVAL;

  printf("Incoming traffic: %llu bytes/s, Outgoing traffic: %llu bytes/s\n",
         rx_speed, tx_speed);

  stats->prev_rx_bytes = stats->total_rx_bytes;
  stats->prev_tx_bytes = stats->total_tx_bytes;

  pthread_mutex_unlock(&stats->lock);
}*/

void calculate_and_print_traffic_speed(TrafficStats *stats) {
  pthread_mutex_lock(&stats->lock);

  // Calculate speed in bytes per second
  unsigned long long rx_speed_bytes =
      (stats->total_rx_bytes - stats->prev_rx_bytes) / INTERVAL;
  unsigned long long tx_speed_bytes =
      (stats->total_tx_bytes - stats->prev_tx_bytes) / INTERVAL;

  // Convert to megabytes per second (1 MB = 1,000,000 bytes)
  double rx_speed_mb = rx_speed_bytes / 1000000.0;
  double tx_speed_mb = tx_speed_bytes / 1000000.0;

  // Print the traffic speed in megabytes per second
  printf("Incoming traffic: %.2f MB/s, Outgoing traffic: %.2f MB/s\n",
         rx_speed_mb, tx_speed_mb);

  // Update the previous byte counts
  stats->prev_rx_bytes = stats->total_rx_bytes;
  stats->prev_tx_bytes = stats->total_tx_bytes;

  pthread_mutex_unlock(&stats->lock);
}

/*void calculate_and_print_traffic_speed(TrafficStats *stats) {
  pthread_mutex_lock(&stats->lock);

  // Calculate speed in bytes per second
  unsigned long long rx_speed_bytes =
      (stats->total_rx_bytes - stats->prev_rx_bytes) / INTERVAL;
  unsigned long long tx_speed_bytes =
      (stats->total_tx_bytes - stats->prev_tx_bytes) / INTERVAL;

  // Convert to megabits per second (1 byte = 8 bits, 1 Mbit = 1,000,000 bits,
  // so 1 Mbit = 125,000 bytes)
  double rx_speed_mbit = rx_speed_bytes / 125000.0;
  double tx_speed_mbit = tx_speed_bytes / 125000.0;

  // Print the traffic speed in megabits per second
  printf("Incoming traffic: %.2f Mbit/s, Outgoing traffic: %.2f Mbit/s\n",
         rx_speed_mbit, tx_speed_mbit);

  // Update the previous byte counts
  stats->prev_rx_bytes = stats->total_rx_bytes;
  stats->prev_tx_bytes = stats->total_tx_bytes;

  pthread_mutex_unlock(&stats->lock);
}*/
#include "trafic_stats.h"

void calculate_and_print_traffic_speed(TrafficStats *stats,
                                       threadpool incomming_pool,
                                       threadpool outgoing_pool) {
  pthread_mutex_lock(&stats->lock);
  struct timespec curr_time;
  clock_gettime(CLOCK_MONOTONIC, &curr_time);

  unsigned long long elapsed_us =
      (curr_time.tv_sec - stats->prev_time.tv_sec) * NS_IN_SECOND +
      curr_time.tv_nsec - stats->prev_time.tv_nsec;

  // Calculate speed in bytes per second
  double rx_speed_bytes =
      ((double)(stats->total_rx_bytes - stats->prev_rx_bytes)) / elapsed_us *
      NS_IN_SECOND;
  double tx_speed_bytes =
      ((double)(stats->total_tx_bytes - stats->prev_tx_bytes)) / elapsed_us *
      NS_IN_SECOND;

  // Convert to megabytes per second (1 MB = 1,000,000 bytes)
  double rx_speed_mb = rx_speed_bytes / (1024.0 * 1024);
  double tx_speed_mb = tx_speed_bytes / (1024.0 * 1024);

  // Print the traffic speed in megabytes per second
  printf(
      "Incoming traffic: %.2lf MB/s, Outgoing traffic: %.2lf MB/s, Inc. pool: "
      "%d, Out. pool: %d, Cached dns packets: %u, Total packets: %llu\n",
      rx_speed_mb, tx_speed_mb, incomming_pool->jobqueue.len,
      outgoing_pool->jobqueue.len, HASH_COUNT(cached_dns_packets),
      stats->total_packets);

  // Update the previous byte counts
  stats->prev_rx_bytes = stats->total_rx_bytes;
  stats->prev_tx_bytes = stats->total_tx_bytes;

  stats->prev_time = curr_time;
  pthread_mutex_unlock(&stats->lock);
}
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define SERVER_IP "127.0.0.1" // IP-адреса UDP сервера
#define SERVER_PORT 8000      // Порт UDP сервера
#define TARGET_SPEED 10 * 1024 * 1024 // Цільова швидкість 10 Мб/с у байтах
#define NS_IN_SECOND 1000000000
#define NS_IN_MKS 1000
#define MKS_IN_SECOND 1000000

#define ADJ_INTERVAL 5 * MKS_IN_SECOND
#define MOVE_TO_SMALL_ADJ_FACTOR 0.1
#define ADJ_FACTOR 0.05
#define SMALL_ADJ_FACTOR 0.01

#define APPLY_MORE 0.1

unsigned char packet[] = {
    0x00, 0x00, // ID: 0
    0x01, 0x00, // Flags: Standard query, recursion desired
    0x00, 0x1e, // QDCOUNT: 30 questions
    0x00, 0x00, // ANCOUNT: 0 answers
    0x00, 0x00, // NSCOUNT: 0 authority records
    0x00, 0x00, // ARCOUNT: 0 additional records

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google" domain label
    0x03, 0x63, 0x6f, 0x6d,                   // "com" domain label
    0x00,                                     // End of domain name
    0x00, 0x01,                               // Type: A (IPv4 address)
    0x00, 0x01,                               // Class: IN (Internet)
};

#define PACKET_SIZE sizeof(packet)

void *adjust_delay(void *arg);
void error_exit(const char *msg);
void sleep_timespec(const unsigned long long nanoseconds);
void onexit(void);
void onsignalexit(int sig);

volatile long long delay_ns = 6 * NS_IN_MKS;
volatile long long sent_bytes = 0;
volatile unsigned long long sent_packets = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int main() {
  int sockfd;
  struct sockaddr_in server_addr;
  struct timespec start_time, end_time;

  pthread_t adjust_thread;

  unsigned long long elapsed_ns;

  // Створення сокета
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    error_exit("Помилка створення сокета");

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);
  inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

  if (atexit(onexit) != 0)
    error_exit("Can't register exit callback");

  signal(SIGINT, onsignalexit);

  // Старт потоку для підлаштування затримки
  if (pthread_create(&adjust_thread, NULL, adjust_delay, NULL) != 0)
    error_exit("Can't create thread");

  // Цикл відправки пакетів
  while (1) {
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    if (sendto(sockfd, packet, sizeof(packet), 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
      perror("Помилка відправки");

    sent_bytes += sizeof(packet);
    ++sent_packets;
    // Вимірювання часу
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * NS_IN_SECOND +
                 end_time.tv_nsec - start_time.tv_nsec;

    // Підтримання затримки
    if (elapsed_ns < delay_ns)
      sleep_timespec(delay_ns - elapsed_ns);
  }

  close(sockfd);
  pthread_cancel(adjust_thread);
  return 0;
}

void *adjust_delay(void *arg) {
  long long prev_sent_bytes = 0;
  unsigned long long bytes_diff;

  unsigned long long elapsed_us;

  struct timespec prev_time, curr_time;
  double current_speed, speed_ratio;

  clock_gettime(CLOCK_MONOTONIC, &prev_time);

  while (1) {
    usleep(ADJ_INTERVAL);
    clock_gettime(CLOCK_MONOTONIC, &curr_time);

    bytes_diff = sent_bytes - prev_sent_bytes;
    elapsed_us = (curr_time.tv_sec - prev_time.tv_sec) * NS_IN_SECOND +
                 curr_time.tv_nsec - prev_time.tv_nsec;

    current_speed =
        (bytes_diff * 1.0 / elapsed_us) * NS_IN_SECOND; // Швидкість у байтах/с
    speed_ratio = (double)TARGET_SPEED / current_speed;

    printf("Current speed: %.2lf MB/s, Total bytes sent: %.2lf MB, Sent "
           "packets: %llu, Sleep time: "
           "%lld ns\n",
           current_speed / (1024 * 1024), (double)sent_bytes / (1024 * 1024),
           sent_packets,
           delay_ns); // Виводимо загальний обсяг даних

    // Коригування затримки
    if (speed_ratio > 1.0)
      delay_ns *= (1.0 - (speed_ratio - 1.0 < MOVE_TO_SMALL_ADJ_FACTOR
                              ? SMALL_ADJ_FACTOR
                              : ADJ_FACTOR));
    else if (1.0 - speed_ratio > APPLY_MORE)
      delay_ns *= (1.0 + (1.0 - speed_ratio < ADJ_FACTOR ? SMALL_ADJ_FACTOR
                                                         : ADJ_FACTOR));

    // Оновлення попередніх значень
    prev_sent_bytes = sent_bytes;
    prev_time = curr_time;
  }
}

void sleep_timespec(const unsigned long long nanoseconds) {
  static struct timespec ts, rem;
  ts.tv_sec = nanoseconds / NS_IN_SECOND;
  ts.tv_nsec = nanoseconds % NS_IN_SECOND;

  if (nanosleep(&ts, &rem) < 0) {
    if (errno == EINTR) {
      printf("Sleep interrupted, remaining time: %ld sec, %ld nsec\n",
             rem.tv_sec, rem.tv_nsec);
    } else {
      perror("nanosleep failed");
    }
  }
}

void error_exit(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

void onsignalexit(int sig) { exit(0); }

void onexit(void) {
  printf("Total bytes sent: %.2lf MB, Sent "
         "packets: %llu, Sleep time: "
         "%lld ns\n",
         (double)sent_bytes / (1024 * 1024), sent_packets,
         delay_ns); // Виводимо загальний обсяг даних
}

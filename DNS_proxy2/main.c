#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 1024

// Встановлення сокета в неблокуючий режим
void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sockfd, max_fd, nready;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);
    fd_set read_fds, all_fds;

    // Створення UDP-сокета
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Не вдалося створити сокет");
        exit(EXIT_FAILURE);
    }

    // Налаштування серверної адреси
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Прив'язка сокета до адреси
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Не вдалося прив'язати сокет");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Встановлення неблокуючого режиму
    set_non_blocking(sockfd);

    // Ініціалізація набору файлових дескрипторів
    FD_ZERO(&all_fds);
    FD_SET(sockfd, &all_fds);
    max_fd = sockfd;

    printf("UDP сервер слухає на порту %d...\n", PORT);

    // Основний цикл сервера
    while (1) {
        read_fds = all_fds;

        // Використовуємо select для очікування на події читання
        nready = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

        if (nready < 0) {
            perror("select помилка");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Перевіряємо, чи є дані для читання на головному сокеті
        if (FD_ISSET(sockfd, &read_fds)) {
            // Отримуємо повідомлення від клієнта
            int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (n > 0) {
                buffer[n] = '\0';
                printf("Отримано від клієнта: %s\n", buffer);

                // Відправляємо відповідь
                const char *response = "Повідомлення отримано!";
                sendto(sockfd, response, strlen(response), 0, (struct sockaddr *)&client_addr, addr_len);
            }
        }
    }

    close(sockfd);
    return 0;
}

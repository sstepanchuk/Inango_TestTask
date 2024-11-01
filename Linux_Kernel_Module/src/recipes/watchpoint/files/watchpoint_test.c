#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main() {
  uint8_t *watch_addr = malloc(sizeof(uint8_t));
  if (!watch_addr) {
    perror("malloc failed");
    return 1;
  }

  // Виведення адреси як unsigned int
  printf("Allocated address for monitoring: %u\n", (unsigned int)watch_addr);

  // Очікування на введення користувачем
  printf("Press Enter to continue...\n");
  getchar(); // Чекає на натискання Enter

  free(watch_addr);
  return 0;
}

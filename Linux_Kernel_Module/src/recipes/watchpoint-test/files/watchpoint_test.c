#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main() {
  uint8_t *watch_addr = malloc(sizeof(uint8_t));
  if (!watch_addr) {
    perror("malloc failed");
    return 1;
  }

  printf("Allocated address for monitoring: %u\n", watch_addr);

  while (1) {
    printf("Current value at address: %u -> %hhu\n", watch_addr, *watch_addr);
    printf("Enter a new value to store at the allocated address (or -1 to "
           "exit): ");

    int new_value;
    if (scanf("%d", &new_value) != 1) {
      perror("Invalid input");
      free(watch_addr);
      return 1;
    }

    if (new_value == -1) {
      break;
    }

    *watch_addr = (uint8_t)new_value;
    printf("Updated value at address: %u -> %hhu\n", watch_addr, *watch_addr);
  }

  free(watch_addr);
  return 0;
}

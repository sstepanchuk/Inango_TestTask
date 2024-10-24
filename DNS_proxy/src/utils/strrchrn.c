#include "strrchrn.h"

int strrchrn(const char *m, const char c, size_t n) {
  while (n--)
    if (m[n] == c)
      return n;
  return -1;
}

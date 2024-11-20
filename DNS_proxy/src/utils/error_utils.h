#ifndef H_ERROR_UTILS
#define H_ERROR_UTILS

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

#define SET_ERROR(str, ...)                                                    \
  do {                                                                         \
    fprintf(stderr, "[%s] -> " str "\n", __func__, ##__VA_ARGS__);             \
  } while (0)

#endif
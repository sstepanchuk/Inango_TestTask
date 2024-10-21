#ifndef H_CHECK_PRETTY_PRINT
#define H_CHECK_PRETTY_PRINT

#include <check.h>
#include <stdio.h>
#include "check_impl.h"

// ANSI escape codes for colors
#define RESET "\033[0m"
#define GREEN "\033[32m"
#define RED "\033[31m"

void print_test_results_tree(SRunner *sr);

#endif
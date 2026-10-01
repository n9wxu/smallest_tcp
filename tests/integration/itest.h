/**
 * @file itest.h
 * @brief What an integration test file includes: the test macros
 *        (tests/unit/test_main.h), the scripted link (wire.h), and
 *        expected failures.
 */

#ifndef ITEST_H
#define ITEST_H

#include "test_main.h"
#include "wire.h"

/* ── Expected failures ────────────────────────────────────────────────
 * A requirement the stack does not meet yet: the test runs and must
 * fail; if it passes, the run fails until RUN_XFAIL becomes RUN_TEST. */

static int test_xfails = 0;

#define RUN_XFAIL(name)                                                        \
  do {                                                                         \
    test_count++;                                                              \
    current_test_failed = 0;                                                   \
    name();                                                                    \
    if (current_test_failed) {                                                 \
      test_failures--;                                                         \
      test_xfails++;                                                           \
      fprintf(stderr, "  XFAIL: %s (not met yet)\n", #name);                   \
    } else {                                                                   \
      test_failures++;                                                         \
      fprintf(stderr, "  XPASS: %s — met now: make it RUN_TEST\n", #name);     \
    }                                                                          \
  } while (0)

#define ITEST_REPORT()                                                         \
  do {                                                                         \
    fprintf(stderr, "\n%d tests, %d passed, %d failed, %d expected to fail\n", \
            test_count, test_count - test_failures - test_xfails,              \
            test_failures, test_xfails);                                       \
  } while (0)

#endif /* ITEST_H */

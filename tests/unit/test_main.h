/**
 * @file test_main.h
 * @brief Minimal C unit test framework — no dependencies.
 *
 * Usage:
 *   TEST(test_name) {
 *       ASSERT_EQ(1, 1);
 *       ASSERT_TRUE(condition);
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_name);
 *       TEST_REPORT();
 *       return test_failures;
 *   }
 */

#ifndef TEST_MAIN_H
#define TEST_MAIN_H

#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int test_failures = 0;
static int current_test_failed = 0;

#define TEST(name) static void name(void)

#define RUN_TEST(name)                                                         \
  do {                                                                         \
    test_count++;                                                              \
    current_test_failed = 0;                                                   \
    name();                                                                    \
    if (current_test_failed) {                                                 \
      fprintf(stderr, "  FAIL: %s\n", #name);                                  \
    } else {                                                                   \
      fprintf(stderr, "  PASS: %s\n", #name);                                  \
    }                                                                          \
  } while (0)

#define TEST_REPORT()                                                          \
  do {                                                                         \
    fprintf(stderr, "\n%d tests, %d passed, %d failed\n", test_count,          \
            test_count - test_failures, test_failures);                        \
  } while (0)

#define ASSERT_TRUE(cond)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "    ASSERT_TRUE failed: %s (%s:%d)\n", #cond, __FILE__, \
              __LINE__);                                                       \
      current_test_failed = 1;                                                 \
      test_failures++;                                                         \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b)                                                        \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      fprintf(stderr, "    ASSERT_EQ failed: %s != %s (%s:%d)\n", #a, #b,      \
              __FILE__, __LINE__);                                             \
      current_test_failed = 1;                                                 \
      test_failures++;                                                         \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NE(a, b)                                                        \
  do {                                                                         \
    if ((a) == (b)) {                                                          \
      fprintf(stderr, "    ASSERT_NE failed: %s == %s (%s:%d)\n", #a, #b,      \
              __FILE__, __LINE__);                                             \
      current_test_failed = 1;                                                 \
      test_failures++;                                                         \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_MEM_EQ(a, b, len)                                               \
  do {                                                                         \
    if (memcmp((a), (b), (len)) != 0) {                                        \
      fprintf(stderr, "    ASSERT_MEM_EQ failed: %s != %s (%s:%d)\n", #a, #b,  \
              __FILE__, __LINE__);                                             \
      current_test_failed = 1;                                                 \
      test_failures++;                                                         \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NULL(ptr) ASSERT_TRUE((ptr) == NULL)
#define ASSERT_NOT_NULL(ptr) ASSERT_TRUE((ptr) != NULL)

#endif /* TEST_MAIN_H */

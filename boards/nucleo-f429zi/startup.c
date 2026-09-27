/**
 * @file boards/nucleo-f429zi/startup.c
 * @brief Cortex-M4 start-up: the vector table, and a reset handler that
 *        copies .data from flash, zeroes .bss and calls main().
 *
 * Only the system exceptions have vectors: the firmware enables no
 * peripheral interrupt.  The symbols come from linker.ld.
 */

#include <stdint.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss;
extern void _estack(void); /* a function type, so the table needs no cast */

int main(void);
void reset_handler(void);
void default_handler(void);
void systick_handler(void);

typedef void (*vector_t)(void);

__attribute__((section(".isr_vector"), used)) const vector_t vectors[16] = {
    _estack,         /* initial stack pointer */
    reset_handler,   /* reset */
    default_handler, /* NMI */
    default_handler, /* hard fault */
    default_handler, /* memory management fault */
    default_handler, /* bus fault */
    default_handler, /* usage fault */
    0,
    0,
    0,
    0,
    default_handler, /* SVCall */
    default_handler, /* debug monitor */
    0,
    default_handler, /* PendSV */
    systick_handler, /* SysTick */
};

void reset_handler(void) {
  uint32_t *src = &_sidata, *dst = &_sdata;
  while (dst < &_edata)
    *dst++ = *src++;
  for (dst = &_sbss; dst < &_ebss;)
    *dst++ = 0;
  main();
  for (;;) {
  }
}

/* A fault or an unexpected exception: stop where a debugger can see it */
void default_handler(void) {
  for (;;) {
  }
}

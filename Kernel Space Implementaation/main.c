#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "sha256.h"

volatile static int started = 0;

// Added missing constant definition
#define SHA256_BLOCK_SIZE 32
#define MAX_INPUT_SIZE 512

// Added kernel-safe string length function
static int k_strlen(const char* s) {
  int n;
  for (n = 0; s[n]; n++)
    ;
  return n;
}

void print_hash(uint8 hash[]) {
  printf("Hash: ");
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
    printf("%x", hash[i] & 0xff);  // Added '0' padding for consistent output
  }
  printf("\n");
}

// Added SHA256 test at boot
static void test_sha256_at_boot(void) {
  const char test_data[] = "hello world";
  uint8 hash[SHA256_BLOCK_SIZE];

  struct SHA256_CTX ctx;

  uint64 startU, endU, startR, endR;
  int iterations = 10000;

  sha256_init(&ctx);
  sha256_update(&ctx, (const uint8*)test_data, k_strlen(test_data));
  sha256_final(&ctx, hash);

  
  intr_on();
  startR = r_time();
  startU = ticks;

  for(int i = 0; i < iterations; i++) {
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8*)test_data, k_strlen(test_data));
    sha256_final(&ctx, hash);
  }

  endU = ticks;
  endR = r_time();
  intr_off();

  uint64 cycles = endR - startR;
  uint64 avg_cycles = cycles / iterations;
    
  printf("Total cycles: %ld\n", cycles);
  printf("Iterations: %d\n", iterations);
  printf("Average cycles per iteration: %ld\n", avg_cycles);

  uint64 completeTicks = endU - startU;
  uint64 avg_ticks = completeTicks / iterations;
  printf("Total ticks: %ld\n", completeTicks);
  printf("Iterations: %d\n", iterations);
  printf("Average ticks per iteration: %ld\n", avg_ticks);

  printf("\nSHA256 Boot Test:\n");
  printf("Input: %s\n", test_data);
  print_hash(hash);
  printf("\n");
}

void
main()
{
  if (cpuid() == 0) {
    consoleinit();
    printfinit();
    printf("\n");
    printf("xv6 kernel is booting\n");
    printf("\n");
    kinit();         // physical page allocator
    kvminit();       // create kernel page table
    kvminithart();   // turn on paging
    procinit();      // process table
    trapinit();      // trap vectors
    trapinithart();  // install kernel trap vector
    plicinit();      // set up interrupt controller
    plicinithart();  // ask PLIC for device interrupts
    binit();         // buffer cache
    iinit();         // inode table
    fileinit();      // file table
    virtio_disk_init(); // emulated hard disk
    userinit();      // first user process

    // Added SHA256 test call
    test_sha256_at_boot();

    __sync_synchronize();
    started = 1;
  }
  else {
    while (started == 0)
      ;
    __sync_synchronize();
    printf("hart %d starting\n", cpuid());
    kvminithart();    // turn on paging
    trapinithart();   // install kernel trap vector
    plicinithart();   // ask PLIC for device interrupts
  }
  scheduler();
}

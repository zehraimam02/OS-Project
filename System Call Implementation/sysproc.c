#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "sysproc.h"
#include "sha256.h" 

int syscall_count;  // Added this field to track system call count

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}


uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// to get system call count
int sys_getsyscallcount(void)
{
    int n;
    argint(0, &n);
    if (n != 0) {
        syscall_count = 0;
    }
    return syscall_count;
}

// to get r_time()
uint64
sys_get_cycle_count(void)
{
    return r_time();
}

int sys_sha256(void) {
  char *input;
  char *output;
  int len;
  int max_len = 1024;
  struct SHA256_CTX ctx;
  uint64 input_addr, output_addr;
  struct proc *p = myproc();
  
  // Get arguments using argaddr
  argaddr(0, &input_addr);
  argaddr(1, &output_addr);
  argint(2, &len);
  
  if(len <= 0 || len > max_len)
    return -1;
    
  // Allocate kernel buffers
  input = kalloc();
  if(input == 0)
    return -1;
    
  output = kalloc();
  if(output == 0) {
    kfree(input);
    return -1;
  }

  // Clear buffers to prevent data leaks
  memset(input, 0, PGSIZE);
  memset(output, 0, PGSIZE);
  
  // Copy input from user space
  if(copyin(p->pagetable, input, input_addr, len) < 0) {
    kfree(input);
    kfree(output);
    return -1;
  }
  
  // Compute hash
  sha256_init(&ctx);
  sha256_update(&ctx, (uint8*)input, len);
  sha256_final(&ctx, (uint8*)output);
  
  // Copy result back to user space
  if(copyout(p->pagetable, output_addr, output, SHA256_BLOCK_SIZE) < 0) {
    kfree(input);
    kfree(output);
    return -1;
  }
  
  kfree(input);
  kfree(output);
  return 0;
}

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

//! added

void exit(int status){
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  thread_exit(); 
}


void halt (void)
{
  shutdown_power_off();
}

void is_valid_addr(void *addr)
{
  if(!is_user_vaddr(addr) || 
    pagedir_get_page(thread_current()->pagedir, addr) == NULL)
  {
    exit(-1);
  }
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *esp = f->esp;
  is_valid_addr(esp);

  switch(*(uint32_t *)(f->esp))
  {
    case SYS_HALT:
      halt();
      break;
    
    case SYS_EXIT:
      is_valid_addr(f->esp+4);
      exit(*(int*)(f->esp+4));
      break;

    case SYS_CREATE:
      break; //! not implemented yet
    
    case SYS_OPEN:
      break; //! not implemented yet

    case SYS_CLOSE:
      break; //! not implemented yet

    case SYS_WRITE:
      break; //! not implemented yet

    default:
      printf("system call!\n");
      thread_exit();

  }

}

//! added
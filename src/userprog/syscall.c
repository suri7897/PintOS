#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

//! added

void exit(int status){
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status); //! exit call
  cur->exit_status = status; //! save exit status
  thread_exit(); 
}


void halt (void)
{
  shutdown_power_off();
}

void is_valid_addr(void *addr)
{
  if(!is_user_vaddr(addr) ||  //! is address user address
    pagedir_get_page(thread_current()->pagedir, addr) == NULL) //! check whether address is in page table.
  {
    exit(-1);
  }
}

int write(int fd, void *buffer, unsigned size){
  struct thread *cur = thread_current();
  if(fd == 1){ //! if fd == 1, then put text in buffer.
    putbuf(buffer, size);
  }
  return -1;
}

bool create(const char*file, unsigned initial_size){
  return true;
} //! not implemented yet

int open(const char *file){
  return 1;
} //! not implemented yet

void close(int fd){
  return;
} //! not implemented yet

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
      is_valid_addr(f->esp+4); //! check whether exit status is valid.
      exit(*(int*)(f->esp+4)); //! do exit.
      break;

    case SYS_CREATE:
      break; //! not implemented yet
    
    case SYS_OPEN:
      break; //! not implemented yet

    case SYS_CLOSE:
      break; //! not implemented yet

    case SYS_WRITE: 
    //! ex) write(1, "hello", 5); 
    //! -> esp : SYS_WRITE, esp + 4 : (fd) = 1, esp + 8 : buffer_pointer (pointer of "hello"), esp + 12 : buffer_size (5)
      is_valid_addr(f->esp + 4); //! check fd is valid
      is_valid_addr(f->esp + 8); //! check buffer_pointer is valid
      is_valid_addr(f->esp + 12); //! check buffer_size is valid
      f->eax = write((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12))); //! store system call return value.
      break;

    default:
      printf("system call!\n");
      thread_exit();

  }

}

//! added
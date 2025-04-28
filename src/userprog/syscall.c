#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <filesys/filesys.h>

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
  return filesys_create(file, initial_size);
}

int open(const char *file) {
  if(file == NULL) { //! check file is NULL
    return -1;
  }
  struct thread *cur = thread_current();
  struct file *f = filesys_open(file);
  if(f == NULL) { //! check file is NULL
    return -1;
  }
  int i = 2; //! Note that 0, 1 is occupied with stdout, stdin.
  while(cur->fdt[i] != NULL && i < 64){ //! search for empty fd table.
    i++;
  }
  if(cur->fdt[i] == NULL){ //! if we found, then add to fdt.
    cur->fdt[i] = f;
    return i;
  }
  //! if fdtable is all full.
  file_close(f);
  return -1;
}

void close(int fd){
  struct thread *cur = thread_current();
  struct file *f;
  f = cur->fdt[fd]; //! find file matching to file descriptor.

  if(f == NULL) //! if not found, then return;
    return;
  
  file_close(f); //! close the file
  cur->fdt[fd] = NULL; //! release fd to NULL.

  return;
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
      is_valid_addr(f->esp+4); //! check whether exit status is valid.
      exit(*(int*)(f->esp+4)); //! do exit.
      break;

    case SYS_CREATE:
      is_valid_addr(f->esp+4);
      is_valid_addr(f->esp+8);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    
    case SYS_OPEN:
      is_valid_addr(f->esp+4);
      f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_CLOSE:
      is_valid_addr(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
      break;

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
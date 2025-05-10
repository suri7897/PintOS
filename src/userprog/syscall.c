#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <filesys/filesys.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "lib/user/syscall.h"
#include "process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

//! added

void exit(int status)
{
    struct thread* cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, status); //! exit call
    cur->exit_status = status; //! save exit status
    thread_exit();
}

void halt(void)
{
    shutdown_power_off();
}

void is_valid_addr(void* addr)
{
    if (!is_user_vaddr(addr) || //! is address user address
        pagedir_get_page(thread_current()->pagedir, addr) == NULL) //! check whether address is in page table.
    {
        exit(-1);
    }
}

int write(int fd, const void* buffer, unsigned size)
{
    is_valid_addr(buffer);
    struct thread* cur = thread_current();
    if (fd < 0 || fd > 128) { //! prevent bad fd_value
      exit(-1); 
    }
    if (fd == 0){
      exit(-1);
    }
    else if (fd == 1) { //! if fd == 1, then put text in buffer.
      putbuf(buffer, size);
    }
    //! project 2-2
    else{
      struct file* f = cur->fdt[fd];
      if(f==NULL){
        exit(-1);
      }
      return file_write(f, buffer, size);
    }
}

bool create(const char* file, unsigned initial_size)
{
    is_valid_addr((void*)file); //! check file's address is valid
    if (file == NULL) { //! if file is NULL -> exit.
        exit(-1);
    }
    return filesys_create(file, initial_size);
}

int open(const char* file)
{
    is_valid_addr((void*)file); //! check file's address is valid
    if (file == NULL) { //! check file is NULL
        exit(-1);
    }
    struct thread* cur = thread_current();
    struct file* f = filesys_open(file);
    if (f == NULL) { //! check file is NULL
        return -1;
    }
    int i = 2; //! Note that 0, 1 is occupied with stdout, stdin.
    while (cur->fdt[i] != NULL && i < 128) { //! search for empty fd table.
        i++;
    }
    if (cur->fdt[i] == NULL) { //! if we found, then add to fdt.
        cur->fdt[i] = f;
        return i;
    }
    //! if fdtable is all full.
    file_close(f);
    return -1;
}

void close(int fd)
{
    struct thread* cur = thread_current();
    struct file* f;
    if (fd < 0 || fd > 128) { //! prevent bad fd_value
        exit(-1);
    }
    f = cur->fdt[fd]; //! find file matching to file descriptor.
    if (f == NULL) //! if not found, then return;
        exit(-1);
    file_close(f); //! close the file
    cur->fdt[fd] = NULL; //! release fd to NULL.

    return;
}

//! Project 2-2

int read(int fd, void *buffer, unsigned size){
  is_valid_addr(buffer); //! check buffer is valid
  struct thread* cur = thread_current();
  if (fd < 0 || fd > 128) { //! prevent bad fd_value
    exit(-1); 
  }
  if (fd == 0){ //! not implemented yet
    // int i;
    // for (i = 0; i < size; i++){
    //   buffer[i] = input_getc();
    // }
  }
  else if (fd >= 2){
    struct file *f = cur->fdt[fd];
    if(f == NULL){
      exit(-1);
    }
    return file_read(cur->fdt[fd], buffer, size);
  }
  return -1;
}

pid_t exec(const char *cmd_line){
  return process_execute(cmd_line);
}

int wait (pid_t pid){
  return process_wait(pid);
}

bool remove (const char* file){
  return filesys_remove(file);
}

int filesize (int fd){
return file_length(thread_current()->fdt[fd]);
}

void seek (int fd, unsigned position){
  file_seek(thread_current()->fdt[fd], position);
}

unsigned tell (int fd){
  return file_tell(thread_current()->fdt[fd]);
}

static void
syscall_handler(struct intr_frame* f UNUSED)
{
    uint32_t* esp = f->esp;
    is_valid_addr(esp);

    switch (*(uint32_t*)(f->esp)) {
    case SYS_HALT:
        halt();
        break;

    case SYS_EXIT:
        is_valid_addr(f->esp + 4); //! check whether exit status is valid.
        exit(*(int*)(f->esp + 4)); //! do exit.
        break;

    case SYS_CREATE:
        is_valid_addr(f->esp + 4);
        is_valid_addr(f->esp + 8);
        f->eax = create((const char*)*(uint32_t*)(f->esp + 4), (unsigned)*(uint32_t*)(f->esp + 8));
        break;

    case SYS_OPEN:
        is_valid_addr(f->esp + 4);
        f->eax = open((const char*)*(uint32_t*)(f->esp + 4));
        break;

    case SYS_CLOSE:
        is_valid_addr(f->esp + 4);
        close((int)*(uint32_t*)(f->esp + 4));
        break;

    case SYS_WRITE:
        //! ex) write(1, "hello", 5);
        //! -> esp : SYS_WRITE, esp + 4 : (fd) = 1, esp + 8 : buffer_pointer (pointer of "hello"), esp + 12 : buffer_size (5)
        is_valid_addr(f->esp + 4); //! check fd is valid
        is_valid_addr(f->esp + 8); //! check buffer_pointer is valid
        is_valid_addr(f->esp + 12); //! check buffer_size is valid
        f->eax = write((int)*(uint32_t*)(f->esp + 4), (const void*)*(uint32_t*)(f->esp + 8), (unsigned)*((uint32_t*)(f->esp + 12))); //! store system call return value.
        break;

    case SYS_READ :
        is_valid_addr(f->esp + 4); 
        is_valid_addr(f->esp + 8); 
        is_valid_addr(f->esp + 12); 
        f->eax = read((int)*(uint32_t*)(f->esp + 4), (void*)*(uint32_t*)(f->esp + 8), (unsigned)*((uint32_t*)(f->esp + 12)));
        break;

    case SYS_EXEC :
        is_valid_addr(f->esp + 4);
        f->eax = exec((const char*)*(uint32_t *)(f->esp + 4));
        break;

    case SYS_WAIT :
        is_valid_addr(f->esp + 4);
        f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
        break;

    case SYS_REMOVE :
        is_valid_addr(f->esp + 4);
        f->eax = remove((const char*)*(uint32_t *)(f->esp + 4));
        break;

    case SYS_FILESIZE :
        is_valid_addr(f->esp + 4);
        f->eax= filesize((int)*(uint32_t*)(f->esp + 4));
        break;

    case SYS_SEEK :
        is_valid_addr(f->esp + 4);
        is_valid_addr(f->esp + 8);
        seek((int)*(uint32_t*)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
        break;

    case SYS_TELL:
        is_valid_addr(f->esp + 4);
        f->eax = tell((int)*(uint32_t *)(f->esp + 4));
        break;
    }
}
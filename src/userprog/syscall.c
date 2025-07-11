#include "userprog/syscall.h"
#include "filesys/file.h"
#include "lib/user/syscall.h"
#include "process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"
#include <filesys/filesys.h>
#include <stdio.h>
#include <syscall-nr.h>

static void syscall_handler(struct intr_frame*);
struct lock file_lock; //! define lock

void syscall_init(void)
{
    lock_init(&file_lock); //! activate lock
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

struct spt_entry* validate_user_addr(void* addr, void* esp)
{
    if (addr < 0x8048000 || addr >= 0xc0000000)
        exit(-1);

    struct spt_entry* spte = find_spte(addr);
    if (spte == NULL) {
        if (!is_user_vaddr(pg_round_down(addr)) || addr < esp - 32 || addr < (void*)(PHYS_BASE - 8 * 1024 * 1024))
            exit(-1);

        expand_stack(addr);
        spte = find_spte(addr);
    }
    return spte;
}

void check_valid_string(void* str, void* esp)
{

    struct spt_entry* spte = validate_user_addr(str, esp);
    if (spte == NULL)
        exit(-1);

    int size = 0;
    while (((char*)str)[size] != '\0')
        size++;

    void* ptr;
    for (ptr = pg_round_down(str); ptr < str + size; ptr += PGSIZE) {
        spte = validate_user_addr(ptr, esp);
        if (spte == NULL)
            exit(-1);
    }
}

void validate_buffer(void* buffer, unsigned size, void* esp, bool to_write)
{
    uintptr_t start = (uintptr_t)buffer;
    uintptr_t end = start + size;
    uintptr_t page;
    for (page = pg_round_down((void*)start);
        page < end;
        page += PGSIZE) {
        struct spt_entry* spte = validate_user_addr((void*)page, esp);
        if (spte == NULL
            || (to_write && !spte->writable)) /* only enforce R/W on writes */
            exit(-1);
    }
}

int write(int fd, const void* buffer, unsigned size)
{
    // is_valid_addr(buffer);
    struct thread* cur = thread_current();
    if (fd < 0 || fd >= 64) { //! prevent bad fd_value
        return -1;
    }

    pin_buffer(buffer, size);
    lock_acquire(&file_lock);

    int result;
    if (fd == 0) {
        result = 1;
    } else if (fd == 1) { //! if fd == 1, then put text in buffer.
        putbuf(buffer, size);
        result = size;
    } else {
        struct file* f = cur->fdt[fd];
        if (f == NULL)
            result = -1;
        else
            result = file_write(f, buffer, size);
    }
    lock_release(&file_lock);
    unpin_buffer(buffer, size);
    return result;
}

bool create(const char* file, unsigned initial_size)
{
    // is_valid_addr((void*)file); //! check file's address is valid
    if (file == NULL) { //! if file is NULL -> exit.
        exit(-1);
    }
    lock_acquire(&file_lock);
    bool result = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return result;
}

int open(const char* file)
{
    // is_valid_addr((void*)file); //! check file's address is valid
    if (file == NULL) { //! check file is NULL
        return -1;
    }
    lock_acquire(&file_lock); //! lock the file_sys
    struct thread* cur = thread_current();
    struct file* f = filesys_open(file);
    if (f == NULL) { //! check file is NULL
        lock_release(&file_lock); //! nothing should be done, so release
        return -1;
    }
    int i = 2; //! Note that 0, 1 is occupied with stdout, stdin.
    while (i < 64 && cur->fdt[i] != NULL) { //! search for empty fd table.
        i++;
    }
    if (cur->fdt[i] == NULL) { //! if we found, then add to fdt.
        cur->fdt[i] = f;
        lock_release(&file_lock); //! nothing should be done, so release
        return i;
    }
    //! if fdtable is all full.
    file_close(f);
    lock_release(&file_lock); //! nothing should be done, so release
    return -1;
}

void close(int fd)
{
    struct thread* cur = thread_current();
    struct file* f;
    if (fd < 0 || fd >= 64) { //! prevent bad fd_value
        return;
    }
    lock_acquire(&file_lock);
    f = cur->fdt[fd]; //! find file matching to file descriptor.
    if (f == NULL) { //! if not found, then return;
        lock_release(&file_lock);
        return;
    }
    file_close(f); //! close the file
    cur->fdt[fd] = NULL; //! release fd to NULL.
    lock_release(&file_lock);

    return;
}

//! Project 2-2

int read(int fd, void* buffer, unsigned size)
{
    // is_valid_addr(buffer); //! check buffer is valid
    struct thread* cur = thread_current();
    if (fd < 0 || fd >= 64) { //! prevent bad fd_value
        return -1;
    }

    int result;
    pin_buffer(buffer, size);
    lock_acquire(&file_lock);
    if (fd == 0) {
        for (result = 0; result < size; result++) {
            *(uint8_t*)(buffer + result) = input_getc();
        }
    } else if (fd == 1)
        result = -1;
    else {
        struct file* f = cur->fdt[fd];
        if (f == NULL) {
            lock_release(&file_lock); //! nothing should be done, so release
            return -1;
        }
        result = file_read(cur->fdt[fd], buffer, size);
    }
    lock_release(&file_lock); //! nothing should be done, so release
    unpin_buffer(buffer, size);
    return result;
}

pid_t exec(const char* cmd_line)
{
    // is_valid_addr(cmd_line);
    if (cmd_line == NULL)
        exit(-1);

    // Make a copy of cmd_line since it's in user memory
    char* cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL)
        exit(-1);

    strlcpy(cmd_copy, cmd_line, PGSIZE);

    // Execute the process and get the child TID
    pid_t pid = process_execute(cmd_copy);

    // Free the copy regardless of execution success
    palloc_free_page(cmd_copy);

    return pid;
}

int wait(pid_t pid)
{
    return process_wait(pid);
}

bool remove(const char* file)
{
    lock_acquire(&file_lock);
    bool result = filesys_remove(file);
    lock_release(&file_lock);
    return result;
}

int filesize(int fd)
{
    return file_length(thread_current()->fdt[fd]);
}

void seek(int fd, unsigned position)
{
    file_seek(thread_current()->fdt[fd], position);
}

unsigned tell(int fd)
{
    return file_tell(thread_current()->fdt[fd]);
}

void pin_buffer(void* start, int size)
{
    void* ptr;
    for (ptr = start; ptr < start + size; ptr += PGSIZE) {
        struct spt_entry* spte = find_spte(ptr);
        spte->pinned = true;
        if (!spte->is_loaded)
            load_physmem(spte);
    }
}

void unpin_buffer(void* start, int size)
{
    void* ptr;
    for (ptr = start; ptr < start + size; ptr += PGSIZE) {
        struct spt_entry* spte = find_spte(ptr);
        spte->pinned = false;
    }
}

int mmap(int fd, void* addr)
{
    int mapid;
    struct mmap_file* m_file;

    // Check arguments: return -1 if the file descriptor is invalid,
    // the address is not in user address space, it's not page-aligned, or addr is NULL
    if (thread_current()->fdt[fd] == NULL || !is_user_vaddr(addr) || pg_ofs(addr) != 0 || addr == NULL)
        return -1;

    // If there's already a spt_entry at addr, we cannot map there
    if (find_spte(addr))
        return -1;

    // Reopen the file to get a dedicated file handle for this mapping
    struct file* reopened_file = file_reopen(thread_current()->fdt[fd]);

    // Allocate a new mapid
    mapid = thread_current()->next_mapid++;

    // Allocate and initialize the mmap_file struct
    m_file = malloc(sizeof(struct mmap_file));
    if (m_file == NULL)
        return -1;
    m_file->mapid = mapid;
    m_file->file = reopened_file;
    list_push_back(&thread_current()->mmap_list, &m_file->elem); // link it into the thread's mmap_list
    list_init(&m_file->spte_list);

    // Create a spt_entry for each page in the file
    int read_bytes = file_length(m_file->file); // total bytes to map
    int ofs = 0;
    while (read_bytes > 0) {
        // Determine how many bytes to read from the file and how many to zero-fill
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        // Allocate and set up a spt_entry
        struct spt_entry* spte = malloc(sizeof(struct spt_entry));
        spte->type = VM_FILE;
        spte->vpage = addr;
        spte->writable = true;
        spte->is_loaded = false;
        spte->file = m_file->file;
        spte->f_offset = ofs;
        spte->read_bytes = page_read_bytes;
        spte->zero_bytes = page_zero_bytes;
        list_push_back(&m_file->spte_list, &spte->mmap_elem);
        insert_spt(&thread_current()->spt, spte);

        // Advance to the next page
        read_bytes -= page_read_bytes;
        ofs += page_read_bytes;
        addr += PGSIZE;
    }

    return mapid;
}

// Unmaps all vm_entries associated with the given mapid
void munmap(int mapid)
{
    struct thread* cur = thread_current();
    struct mmap_file* m_file = NULL;

    // Search the thread's mmap_list for the matching mapid
    struct list_elem* e;
    for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); e = list_next(e)) {
        struct mmap_file* mf = list_entry(e, struct mmap_file, elem);
        if (mf->mapid == mapid) {
            m_file = mf;
            break;
        }
    }

    // If no matching mapping was found, do nothing
    if (m_file == NULL)
        return;

    // Perform the unmapping: remove vm_entries, clear page table entries,
    // free resources, and close the file
    for (e = list_begin(&m_file->spte_list); e != list_end(&m_file->spte_list);) {
        struct spt_entry* spte = list_entry(e, struct spt_entry, mmap_elem);
        struct list_elem* next = list_next(e);

        if (spte->is_loaded && pagedir_is_dirty(thread_current()->pagedir, spte->vpage)) {
            lock_acquire(&file_lock);
            file_write_at(spte->file, spte->vpage, spte->read_bytes, spte->f_offset);
            lock_release(&file_lock);
        }

        if (spte->is_loaded) {
            pagedir_clear_page(cur->pagedir, spte->vpage);
            spte->is_loaded = false;
        }

        hash_delete(&cur->spt, &spte->elem);
        list_remove(&spte->mmap_elem);
        free(spte);

        e = next;
    }

    lock_acquire(&file_lock);
    file_close(m_file->file);
    lock_release(&file_lock);

    list_remove(&m_file->elem);
    free(m_file);
}

//* WE NEED TO STORE ARGUMENTS IN USER STACK TO KERNEL STACK
void store_argument(void* esp, int arg[], int count)
{
    void* ptr = esp + 4;
    int i = 0;
    for (i = 0; i < count; i++) {
        validate_user_addr(ptr, esp);
        arg[i] = *(int*)ptr;
        ptr += 4;
    }
}

static void
syscall_handler(struct intr_frame* f UNUSED)
{
    uint32_t* esp = f->esp;
    validate_user_addr(esp, f->esp);

    int arg[5];

    switch (*(uint32_t*)(f->esp)) {
    case SYS_HALT:
        halt();
        break;

    case SYS_EXIT:
        store_argument(esp, arg, 1);
        exit((int)arg[0]);
        break;

    case SYS_CREATE:
        store_argument(esp, arg, 2);
        check_valid_string((void*)arg[0], f->esp);
        f->eax = create((const char*)arg[0], (unsigned)arg[1]);
        break;

    case SYS_OPEN:
        store_argument(esp, arg, 1);
        check_valid_string((void*)arg[0], f->esp);
        f->eax = open((const char*)arg[0]);
        break;

    case SYS_CLOSE:
        store_argument(esp, arg, 1);
        close((int)arg[0]);
        break;

    case SYS_WRITE:
        store_argument(esp, arg, 3);
        validate_buffer((void*)arg[1], (unsigned)arg[2], f->esp, false);
        f->eax = write((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
        break;

    case SYS_READ:
        store_argument(esp, arg, 3);
        validate_buffer((void*)arg[1], (unsigned)arg[2], f->esp, true);
        f->eax = read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
        break;

    case SYS_EXEC:
        store_argument(esp, arg, 1);
        check_valid_string((void*)arg[0], f->esp);
        f->eax = exec((const char*)arg[0]);
        break;

    case SYS_WAIT:
        store_argument(esp, arg, 1);
        f->eax = wait((int)arg[0]);
        break;

    case SYS_REMOVE:
        store_argument(esp, arg, 1);
        check_valid_string((void*)arg[0], f->esp);
        f->eax = remove((const char*)arg[0]);
        break;

    case SYS_FILESIZE:
        store_argument(esp, arg, 1);
        f->eax = filesize((int)arg[0]);
        break;

    case SYS_SEEK:
        store_argument(esp, arg, 2);
        seek((int)arg[0], (unsigned)arg[1]);
        break;

    case SYS_TELL:
        store_argument(esp, arg, 1);
        f->eax = tell((int)arg[0]);
        break;

        //! Project 3

    case SYS_MMAP:
        store_argument(esp, arg, 2);
        f->eax = mmap((int)arg[0], (void*)arg[1]);
        break;

    case SYS_MUNMAP:
        store_argument(esp, arg, 1);
        munmap((int)arg[0]);
        break;

        //! Project 4

    case SYS_CHDIR:
        thread_exit();

    case SYS_MKDIR:
        thread_exit();

    case SYS_READDIR:
        thread_exit();

    case SYS_ISDIR:
        thread_exit();

    case SYS_INUMBER:
        thread_exit();
    }
}

//! Project 2

// SYS_HALT,                   /* Halt the operating system. */
// SYS_EXIT,                   /* Terminate this process. */
// SYS_EXEC,                   /* Start another process. */
// SYS_WAIT,                   /* Wait for a child process to die. */
// SYS_CREATE,                 /* Create a file. */
// SYS_REMOVE,                 /* Delete a file. */
// SYS_OPEN,                   /* Open a file. */
// SYS_FILESIZE,               /* Obtain a file's size. */
// SYS_READ,                   /* Read from a file. */
// SYS_WRITE,                  /* Write to a file. */
// SYS_SEEK,                   /* Change position in a file. */
// SYS_TELL,                   /* Report current position in a file. */
// SYS_CLOSE,                  /* Close a file. */

//! Project 3

// SYS_MMAP,                   /* Map a file into memory. */
// SYS_MUNMAP,                 /* Remove a memory mapping. */

//! Project 4

// SYS_CHDIR,                  /* Change the current directory. */
// SYS_MKDIR,                  /* Create a directory. */
// SYS_READDIR,                /* Reads a directory entry. */
// SYS_ISDIR,                  /* Tests if a fd represents a directory. */
// SYS_INUMBER                 /* Returns the inode number for a fd. */
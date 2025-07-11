#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "debug.h"
#include "filesys/file.h"
#include "lib/kernel/hash.h"

enum vm_type {
    VM_BIN, // loaded from the executable
    VM_FILE, // loaded from some file mapping
    VM_ANON // anonymous (stack/heap/BSS), lives in swap after eviction
};

struct spt_entry {
    enum vm_type type;
    void* vpage;
    bool is_loaded; // true if page is in memory
    bool writable;
    bool pinned;

    size_t swap_index; // if type==VM_ANON and evicted, which swap slot
    struct file* file;
    size_t f_offset;
    size_t read_bytes;
    size_t zero_bytes;

    struct hash_elem elem;
    struct list_elem mmap_elem;
};

struct mmap_file {
    int mapid;
    struct file* file;
    struct list_elem elem;
    struct list spte_list;
};

static unsigned spt_hash_func(const struct hash_elem*, void*);
static bool spt_less_func(const struct hash_elem*, const struct hash_elem*, void*);
void spt_init(struct hash* spt);
bool insert_spt(struct hash* spt, struct spt_entry* spte);
bool delete_spt(struct hash* spt, struct spt_entry* spte);
struct spt_entry* find_spte(void* vaddr);
static void spt_hash_destructor(struct hash_elem* e, void* aux UNUSED);
void spt_hash_destroy(struct hash* spt);

#endif
#include "vm/page.h"
#include "hash.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static unsigned spt_hash_func(const struct hash_elem* e, void* aux UNUSED)
{
    struct spt_entry* spt_entry = hash_entry(e, struct spt_entry, elem);
    return hash_int((int)(uintptr_t)spt_entry->vpage);
}

static bool spt_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED)
{
    const struct spt_entry* spt_a = hash_entry(a, struct spt_entry, elem);
    const struct spt_entry* spt_b = hash_entry(b, struct spt_entry, elem);
    return spt_a->vpage < spt_b->vpage;
}

void spt_init(struct hash* spt)
{
    hash_init(spt, spt_hash_func, spt_less_func, NULL);
}

bool insert_spt(struct hash* spt, struct spt_entry* spte)
{
    // struct thread *t = thread_current();
    spte->pinned = false;
    if (hash_insert(spt, &spte->elem) == NULL)
        return true;
    else
        return false;
}

bool delete_spt(struct hash* spt, struct spt_entry* spte)
{
    // struct thread *t = thread_current();
    if (hash_delete(spt, &spte->elem) == NULL) {
        return false;
    } else {
        frame_free_page(pagedir_get_page(thread_current()->pagedir, spte->vpage));
        free(spte);
        return true;
    }
}

struct spt_entry* find_spte(void* vaddr)
{
    struct spt_entry spt;
    struct hash_elem* e;
    struct thread* t = thread_current();

    spt.vpage = pg_round_down(vaddr);
    e = hash_find(&t->spt, &spt.elem);

    if (e == NULL)
        return NULL;
    return hash_entry(e, struct spt_entry, elem);
}

static void spt_hash_destructor(struct hash_elem* e, void* aux UNUSED)
{
    struct spt_entry* spt = hash_entry(e, struct spt_entry, elem);
    free(spt);
}

void spt_hash_destroy(struct hash* spt)
{
    hash_destroy(spt, spt_hash_destructor);
}

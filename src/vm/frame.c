#include "vm/frame.h"
#include "frame.h"
#include "list.h"
#include "page.h"
#include "swap.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static struct list frame_table;
static struct lock frame_lock;
static struct list_elem* clock_hand;

void init_frame_table(void)
{
    list_init(&frame_table);
    lock_init(&frame_lock);
    clock_hand = NULL;
}

static struct frame* select_victim(void)
{
    if (list_empty(&frame_table))
        return NULL;

    while (true) {
        if (clock_hand == NULL || clock_hand == list_end(&frame_table))
            clock_hand = list_begin(&frame_table);

        struct frame* f = list_entry(clock_hand, struct frame, elem);
        struct thread* t = f->owner;
        if (t->pagedir == NULL) { // Skip if thread has exited
            clock_hand = list_next(clock_hand);
            continue;
        }

        bool is_upage_acceessed = pagedir_is_accessed(t->pagedir, f->spte->vpage);
        if (is_upage_acceessed || f->spte->pinned) {
            /* Second chance */
            pagedir_set_accessed(t->pagedir, f->spte->vpage, false);
        } else {
            /* Found the victim */
            return f;
        }

        clock_hand = list_next(clock_hand);
    }
}

static void evict_frame(struct frame* victim)
{
    struct thread* t = victim->owner;

    bool is_udirty = pagedir_is_dirty(t->pagedir, victim->spte->vpage);
    switch (victim->spte->type) {
    case VM_BIN:
        if (is_udirty) {
            victim->spte->swap_index = swap_out(victim->kpage);
            victim->spte->type = VM_ANON;
        }
        break;
    case VM_FILE:
        if (is_udirty)
            file_write_at(victim->spte->file, victim->spte->vpage, victim->spte->read_bytes, victim->spte->f_offset);
        break;
    case VM_ANON:
        victim->spte->swap_index = swap_out(victim->kpage);
        break;
    }

    victim->spte->is_loaded = false;

    if (&victim->elem == clock_hand)
        clock_hand = list_next(clock_hand);
    list_remove(&victim->elem);
    pagedir_clear_page(t->pagedir, pg_round_down(victim->spte->vpage));
    palloc_free_page(victim->kpage);
    free(victim);
}

struct frame* frame_get_page()
{
    lock_acquire(&frame_lock);
    void* kpage = palloc_get_page(PAL_USER | PAL_ZERO); // allocate physical page
    while (kpage == NULL) { // allocation fail -> eviction
        struct frame* victim = select_victim();
        if (victim == NULL) {
            lock_release(&frame_lock);
            PANIC("No frames available and no victim selected");
        }
        evict_frame(victim);
        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    }

    struct frame* f = malloc(sizeof(struct frame)); // allocate frame
    if (f == NULL) {
        palloc_free_page(kpage);
        lock_release(&frame_lock);
        return NULL;
    }

    f->kpage = kpage;
    f->owner = thread_current();
    list_push_back(&frame_table, &f->elem);

    lock_release(&frame_lock);
    return f;
}

void frame_free_page(void* free_kpage)
{
    ASSERT(free_kpage != NULL);
    lock_acquire(&frame_lock);

    struct list_elem* e;

    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
        struct frame* f = list_entry(e, struct frame, elem);
        if (f->kpage == free_kpage) {
            if (&f->elem == clock_hand)
                clock_hand = list_next(clock_hand);
            list_remove(&f->elem);
            pagedir_clear_page(f->owner->pagedir, pg_round_down(f->spte->vpage));
            palloc_free_page(f->kpage);
            free(f);
            lock_release(&frame_lock);
            return;
        }
    }

    lock_release(&frame_lock);
    PANIC("Attempted to free a non-existent frame");
}
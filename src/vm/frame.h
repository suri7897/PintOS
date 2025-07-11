#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "list.h"
#include "page.h"

static struct list frame_table;
static struct lock frame_lock;
static struct list_elem* clock_hand;

struct frame {
    void* kpage; // kernal page (physical page)
    struct spt_entry* spte;
    struct thread* owner; // owner thread
    struct list_elem elem; // elem for frame_table
};

void init_frame_table(void);
struct frame* frame_get_page();
void frame_free_page(void* free_kpage);

#endif
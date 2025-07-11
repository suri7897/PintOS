#include "vm/swap.h"
#include "bitmap.h"
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct block* swap_block;
static struct bitmap* swap_map; // 0: free, 1: in use

void swap_init(void)
{
    swap_block = block_get_role(BLOCK_SWAP);
    size_t n_pages = block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE);
    swap_map = bitmap_create(n_pages);
}

size_t swap_out(void* kpage)
{
    size_t slot = bitmap_scan_and_flip(swap_map, 0, 1, false);
    if (slot == BITMAP_ERROR) {
        return BITMAP_ERROR;
    }

    size_t i;
    for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
        block_write(swap_block, slot * (PGSIZE / BLOCK_SECTOR_SIZE) + i, kpage + i * BLOCK_SECTOR_SIZE);

    return slot;
}

void swap_in(size_t slot, void* kpage)
{
    if (bitmap_test(swap_map, slot)) {
        size_t i;
        for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
            block_read(swap_block, slot * (PGSIZE / BLOCK_SECTOR_SIZE) + i, kpage + i * BLOCK_SECTOR_SIZE);

        bitmap_reset(swap_map, slot);
    }
}
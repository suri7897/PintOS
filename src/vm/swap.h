#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
/* Write the 4 KB page at kernel address KPAGE to swap.
   Returns the swap‐slot index you used, or BITMAP_ERROR on failure. */
size_t swap_out(void* kpage);

/* Read the page at swap‐slot INDEX back into KPAGE. */
void swap_in(size_t index, void* kpage);

#endif
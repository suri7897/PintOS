#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define MAX_DIRECT_IDX 124
#define MAX_INDIRECT_IDX 128



/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct_block[MAX_DIRECT_IDX];
    block_sector_t indirect_block_sec; // entry offset of first indirect block
    block_sector_t double_indirect_block_sec; // entry offset of second indirect block.
  };

enum direct_method //* indicate the method to point disk block
{
  DIRECT, //* use direct block
  INDIRECT, //* use indirect block
  DOUBLE_INDIRECT, //* use double indirect block
  OUT_LIMIT //* wrong offset
};

  /*
  * changed structure : change file structure to use direct, indirect, double_indirect block.
  * In maximum, about 8MB of file can be allocated.
  */

struct sector_location {
  enum direct_method method;
  int first_idx;
  int second_idx;
};

struct inode_indirect_block {
  block_sector_t indirect_block[MAX_INDIRECT_IDX];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    // struct inode_disk data;             /* Inode content. */ 
    //* inode_disk is erased
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

static void save_secloc (off_t pos, struct sector_location *sec_loc){ //* save location of sector corresponding to pos in sec_loc.
  
  off_t pos_idx = pos / BLOCK_SECTOR_SIZE;

  if(pos_idx < (off_t)MAX_DIRECT_IDX) //* if we can handle in direct method
  { 
    sec_loc->method = DIRECT;
    sec_loc->first_idx = -1; //* first, second idx is not needed, since it is direct.
    sec_loc->second_idx = -1;
  } 
  else if(pos_idx < (off_t)(MAX_DIRECT_IDX + MAX_INDIRECT_IDX)) //* indirect method
  { 
    sec_loc->method = INDIRECT;
    sec_loc->first_idx = pos_idx - (off_t)MAX_DIRECT_IDX;
    sec_loc->second_idx = -1;
  } 
  else if(pos_idx < (off_t)(MAX_DIRECT_IDX + MAX_INDIRECT_IDX + MAX_INDIRECT_IDX * MAX_INDIRECT_IDX)) 
  {
    sec_loc->method = DOUBLE_INDIRECT;
    off_t doub_ind_idx = pos_idx - MAX_DIRECT_IDX - MAX_INDIRECT_IDX; 
    sec_loc->first_idx = doub_ind_idx / MAX_INDIRECT_IDX;
    sec_loc->second_idx = doub_ind_idx % MAX_INDIRECT_IDX;
  } 
  else 
  {
    sec_loc->method = OUT_LIMIT;
    sec_loc->first_idx = -1;
    sec_loc->second_idx = -1;
  }
}

static bool register_direct(struct inode_disk* inode_disk, block_sector_t new_sector, int index) {
  inode_disk->direct_block[index] = new_sector;
  return true;
}

static bool register_indirect(block_sector_t *indirect_sec_ptr, block_sector_t new_sector, int index) {
  struct inode_indirect_block block;

  if (*indirect_sec_ptr == 0) {
    if (!free_map_allocate(1, indirect_sec_ptr))
      return false;
    memset(&block, 0, sizeof block);
  } else {
    block_read(fs_device, *indirect_sec_ptr, &block);
  }

  block.indirect_block[index] = new_sector;
  block_write(fs_device, *indirect_sec_ptr, &block);
  return true;
}

static bool register_double_indirect(block_sector_t *double_indirect_ptr, block_sector_t new_sector, int outer_idx, int inner_idx) {
  struct inode_indirect_block outer, inner;

  if (*double_indirect_ptr == 0) {
    if (!free_map_allocate(1, double_indirect_ptr))
      return false;
    memset(&outer, 0, sizeof outer);
  } else {
    block_read(fs_device, *double_indirect_ptr, &outer);
  }

  if (outer.indirect_block[outer_idx] == 0) {
    if (!free_map_allocate(1, &outer.indirect_block[outer_idx]))
      return false;
    memset(&inner, 0, sizeof inner);
    block_write(fs_device, outer.indirect_block[outer_idx], &inner);
    block_write(fs_device, *double_indirect_ptr, &outer);
  } else {
    block_read(fs_device, outer.indirect_block[outer_idx], &inner);
  }

  inner.indirect_block[inner_idx] = new_sector;
  block_write(fs_device, outer.indirect_block[outer_idx], &inner);
  return true;
}

static bool register_sector(struct inode_disk* inode_disk, block_sector_t new_sector, struct sector_location sec_loc) {
  switch (sec_loc.method) {
    case DIRECT:
      return register_direct(inode_disk, new_sector, sec_loc.first_idx);

    case INDIRECT:
      return register_indirect(&inode_disk->indirect_block_sec, new_sector, sec_loc.first_idx);

    case DOUBLE_INDIRECT:
      return register_double_indirect(&inode_disk->double_indirect_block_sec, new_sector, sec_loc.first_idx, sec_loc.second_idx);

    default:
      return false;
  }
}


static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
  block_sector_t sector_num = -1; //* -1 indicate error

  if(pos < inode_disk->length){
    struct inode_indirect_block *ind_block;
    struct sector_location sec_loc;
    save_secloc(pos, &sec_loc);

    switch (sec_loc.method)
    {
    case DIRECT: 
      sector_num = inode_disk->direct_block[pos/BLOCK_SECTOR_SIZE];
      break;
    case INDIRECT:
      ind_block = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
      if(ind_block == NULL){
        break;
      }
      else
      {
        block_read(fs_device, inode_disk->indirect_block_sec, ind_block);
        sector_num = ind_block->indirect_block[sec_loc.first_idx];
      }
      free(ind_block);
      break;
    case DOUBLE_INDIRECT:
      ind_block = (struct inode_indirect_block *)malloc(BLOCK_SECTOR_SIZE);
      if(ind_block == NULL)
        break;
      block_read(fs_device, inode_disk->indirect_block_sec, ind_block);
      block_sector_t double_ind_sector = ind_block->indirect_block[sec_loc.first_idx];
      
      if(double_ind_sector == 0){
        free(ind_block);
        break;
      }

      block_read(fs_device, double_ind_sector, ind_block);
      sector_num = ind_block->indirect_block[sec_loc.second_idx];
      free(ind_block);
      break;

    default:
      break;
    }
  }

  return sector_num;
}

static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk){ //* get inode from disk
  block_read(fs_device, inode->sector, inode_disk);
  return true;
}

static void free_direct_block(struct inode_disk *inode_disk) {
  int i;
  for (i = 0; i < MAX_DIRECT_IDX; i++) {
    if (inode_disk->direct_block[i] != 0)
      free_map_release(inode_disk->direct_block[i], 1);
  }
}

static void free_indirect_block(struct inode_disk *inode_disk) {
  if (inode_disk->indirect_block_sec == 0)
    return;

  struct inode_indirect_block block;
  block_read(fs_device, inode_disk->indirect_block_sec, &block);

  int i;
  for (i = 0; i < MAX_INDIRECT_IDX; i++) {
    if (block.indirect_block[i] != 0)
      free_map_release(block.indirect_block[i], 1);
  }

  free_map_release(inode_disk->indirect_block_sec, 1);
}

static void free_double_indirect_block(struct inode_disk *inode_disk) {
  if (inode_disk->double_indirect_block_sec == 0)
    return;

  struct inode_indirect_block outer_block;
  block_read(fs_device, inode_disk->double_indirect_block_sec, &outer_block);
  
  int i;
  for (i = 0; i < MAX_INDIRECT_IDX; i++) {
    block_sector_t inner_sec = outer_block.indirect_block[i];
    if (inner_sec == 0)
      continue;

    struct inode_indirect_block inner_block;
    block_read(fs_device, inner_sec, &inner_block);

    int j;
    for (j = 0; j < MAX_INDIRECT_IDX; j++) {
      if (inner_block.indirect_block[j] != 0)
        free_map_release(inner_block.indirect_block[j], 1);
    }

    free_map_release(inner_sec, 1);
  }

  free_map_release(inode_disk->double_indirect_block_sec, 1);
}

static void free_inode_blocks(struct inode_disk *inode_disk) {
  free_direct_block(inode_disk);
  free_indirect_block(inode_disk);
  free_double_indirect_block(inode_disk);
}

block_sector_t *get_sector_ptr(struct inode_disk *inode_disk, struct sector_location *loc) {
  static struct inode_indirect_block indirect, outer, inner;

  switch (loc->method) {
    case DIRECT:
      return &inode_disk->direct_block[loc->first_idx];

    case INDIRECT:
      if (inode_disk->indirect_block_sec == 0)
        return NULL;

      block_read(fs_device, inode_disk->indirect_block_sec, &indirect);
      return &indirect.indirect_block[loc->first_idx];

    case DOUBLE_INDIRECT:
      if (inode_disk->double_indirect_block_sec == 0)
        return NULL;

      block_read(fs_device, inode_disk->double_indirect_block_sec, &outer);
      block_sector_t inner_sec = outer.indirect_block[loc->first_idx];

      if (inner_sec == 0)
        return NULL;

      block_read(fs_device, inner_sec, &inner);
      return &inner.indirect_block[loc->second_idx];
  }

  return NULL;
}

bool check_sector_allocation(struct inode_disk *inode_disk, off_t sector_index) {
  struct sector_location loc;
  save_secloc(sector_index * BLOCK_SECTOR_SIZE, &loc);

  block_sector_t *target = get_sector_ptr(inode_disk, &loc);
  if (target == NULL)
    return false;

  if (*target == 0) {
    if (!free_map_allocate(1, target))
      return false;

    if (!register_sector(inode_disk, *target, loc))
      return false;
  }

  return true;
}

bool inode_grow(struct inode_disk *inode_disk, off_t old_pos, off_t new_pos) {
  off_t old_sec = old_pos / BLOCK_SECTOR_SIZE;
  off_t new_sec = (new_pos - 1) / BLOCK_SECTOR_SIZE;

  off_t sec;
  for (sec = old_sec; sec <= new_sec; sec++) {
    if (!check_sector_allocation(inode_disk, sec))
      return false;
  }

  off_t new_len = (new_sec + 1) * BLOCK_SECTOR_SIZE;
  if (inode_disk->length < new_len)
    inode_disk->length = new_len;

  return true;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      if(length > 0){
        
        if(!inode_grow(disk_inode, 0, length)){
          free(disk_inode);
          return false;
        }
      }
      block_write(fs_device, sector, disk_inode);
      free(disk_inode);
      success = true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  // block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk *disk_inode = malloc(sizeof(struct inode_disk));
        if (disk_inode != NULL) {
          get_disk_inode(inode, disk_inode);  
          free_inode_blocks(disk_inode);  
          free_map_release(inode->sector, 1);
          free(disk_inode);
          }
        }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  struct inode_disk *disk_inode = malloc(sizeof(struct inode_disk));
  if (disk_inode == NULL)
    return 0;
  get_disk_inode(inode, disk_inode);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);
  free (disk_inode);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  struct inode_disk *disk_inode = malloc(sizeof(struct inode_disk));
  if (disk_inode == NULL)
    return 0;
  get_disk_inode(inode, disk_inode);

  off_t write_end = offset + size;
  if (write_end > disk_inode->length) {
    if (!inode_grow(disk_inode, disk_inode->length, write_end)) {
      free(disk_inode);
      return 0;
    }
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  
  block_write(fs_device, inode->sector, disk_inode);
  
  free (bounce);
  free(disk_inode);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length(const struct inode *inode)
{
  struct inode_disk *inode_disk = malloc(sizeof(struct inode_disk));
  if (inode_disk == NULL)
    return 0;

  get_disk_inode(inode, inode_disk);
  off_t length = inode_disk->length;

  free(inode_disk);
  return length;
}
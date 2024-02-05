#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

//our code

// the number of sectors in one page
#define SECTOR_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

struct anon_page {
    enum vm_type type;
    bool swapped;   // 안필요할수도 있음
    disk_sector_t sector_number; //bitmap_no * SECTOR_PER_PAGE
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

// our code
disk_sector_t find_free_sector(void);
void disk_read_page (struct page *page, void *kva);
void disk_write_page (disk_sector_t sector, struct page *page);

#endif

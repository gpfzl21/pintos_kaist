/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

#include "threads/malloc.h"
#include "threads/mmu.h"
// #include <bitmap.h>

// the number of sectors in one page
#define SECTOR_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};


//our code
static const struct bitmap *swap_table;
static size_t swap_table_size;


//our functions
disk_sector_t
find_free_sector(){
//disk_write (struct disk *, disk_sector_t, const void *); 에 들어갈 disk sector return함
	
	size_t free_page_number = bitmap_scan(swap_table, 0, 1, 0);
	ASSERT(free_page_number != BITMAP_ERROR);
	return SECTOR_PER_PAGE * free_page_number;

}

void
disk_read_page (struct page *page, void *kva){
	
	disk_sector_t sector = page->anon.sector_number;

	for (int i = 0; i < SECTOR_PER_PAGE; i++) {
		// frame에 해당 내용 기록
		disk_read(swap_disk, sector + i, kva + (DISK_SECTOR_SIZE * i));

	}
	page->anon.swapped = false;
	bitmap_set(swap_table, sector/SECTOR_PER_PAGE, 0); 
}

// copy page's content into disk with proper size
void
disk_write_page (disk_sector_t sector, struct page *page){

	// frame의 contents 복사
	for (int i = 0; i < SECTOR_PER_PAGE; i++) {
		disk_write(swap_disk, sector + i, (page->frame->kva) + (DISK_SECTOR_SIZE * i));
	}
	page->anon.swapped = true;
	page->anon.sector_number = sector;

	bitmap_set(swap_table, sector/SECTOR_PER_PAGE, 1);
}


/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// swap_disk = NULL;
	swap_disk = disk_get(1, 1);
	disk_sector_t swap_disk_size = disk_size(swap_disk);
	swap_table = bitmap_create(swap_disk_size / SECTOR_PER_PAGE);
	swap_table_size = bitmap_size(swap_table);

}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	// our code: 빈 anon_page에 대한 정보 업데이트
	anon_page->type = type;
	anon_page->swapped = false;

	struct frame *frame = find_frame(kva);

	if (frame != NULL)
		return true;
	else
		return false;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	
	if (!anon_page->swapped) 
		return false;
	
	// kva에 있는 frame에 읽은 내용 저장. 
	disk_read_page(page, kva);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (page->frame == NULL || page->anon.swapped) {
		return false;
	}
	disk_sector_t sector = find_free_sector();
	disk_write_page(sector, page); // swap table 관리도 해줌
	

	// frame 연결 끊어주는건 caller가 수행함
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	// free(anon_page);는 caller가 수행함

	disk_sector_t sector = anon_page->sector_number;

	bitmap_set(swap_table, sector/SECTOR_PER_PAGE, 0);
}

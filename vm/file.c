/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

// mycode
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

// our code
static struct lock filesys_lock;


/* The initializer of file vm */
void
vm_file_init (void) {
	lock_init(&filesys_lock);
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	// file_page->infos 먼저 바꿔주는 이유는 page->uninit과 page->file는 서로 침범할 수 있기 때문이다.
	file_page->infos = (struct informations *)page->uninit.aux;
	file_page->type = type;
	file_page->swapped = false;
	

	struct frame *frame = find_frame(kva);

	if (frame != NULL)
		return true;
	else
		return false;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	// printf("file_backed_swap_in start\n");
	struct file_page *file_page UNUSED = &page->file;
	bool ret = false;
	
	lock_acquire(&filesys_lock);

	if (!file_page->swapped) {
		// printf("file_backed_swap_in fail because not swapped\n");
		goto err;
	}

	struct informations *infos = file_page->infos;

	size_t page_read_bytes = infos->page_read_bytes;
	size_t page_zero_bytes = infos->page_zero_bytes;
	struct file *file = infos->file;
	off_t ofs = infos->ofs;

	file_seek(file, ofs);
	off_t x = file_read(file, kva, page_read_bytes);	//for debug
	if (x != (int) page_read_bytes) {
		goto err;
	}
	memset(kva + page_read_bytes, 0, page_zero_bytes);

	ret = true;

err:
	lock_release(&filesys_lock);
	return ret;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	bool ret = false;
	struct frame *frame = page->frame;
	
	lock_acquire(&filesys_lock);

	if (frame == NULL || page->file.swapped) {
		goto err;
	}

	if (!pml4_is_dirty(thread_current()->pml4, page->va)) {
		page->file.swapped = true;
		ret = true;
		goto err;
	}

	// write back
	struct informations *infos = file_page->infos;

	size_t page_read_bytes = infos->page_read_bytes;
	size_t page_zero_bytes = infos->page_zero_bytes;
	struct file *file = infos->file;
	off_t ofs = infos->ofs;

	file_seek(file, ofs);
	ASSERT(file_write(file, frame->kva, page_read_bytes) == (int) page_read_bytes);

	page->file.swapped = true;

	// turn off dirty bit
	pml4_set_dirty(thread_current()->pml4, page->va, 0);

	ret = true;
err:

	lock_release(&filesys_lock);
	return ret;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	
	struct thread *t = thread_current();
	if (!pml4_is_dirty (t->pml4, page->va)){
		return;
	}

	struct frame *frame = page->frame;

	struct informations *infos = file_page->infos;

	size_t page_read_bytes = infos->page_read_bytes;
	size_t page_zero_bytes = infos->page_zero_bytes;
	struct file *file = infos->file;
	off_t ofs = infos->ofs;

	file_seek(file, ofs);
	ASSERT(file_write(file, frame->kva, page_read_bytes) == (int) page_read_bytes);
}

// mycode
static bool
lazy_load_file_page (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	struct frame *frame = page->frame;
	struct informations *infos = (struct informations *)aux;

	size_t page_read_bytes = infos->page_read_bytes;
	size_t page_zero_bytes = infos->page_zero_bytes;
	struct file *file = infos->file;
	off_t ofs = infos->ofs;

	file_seek(file, ofs);
	off_t x = file_read(file, frame->kva, page_read_bytes);	//for debug
	if (x != (int) page_read_bytes) {
		// frame dealloc 해야할까?
		return false;
	}
	memset((frame->kva) + page_read_bytes, 0, page_zero_bytes);
	
	return true; 
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// printf("do_mmap start\n");
	// address 리턴할 때 마지막 어드레스인가, 처음의 어드레스인가?
	// load segment와 기능은 유사
	// 예외처리 나중에

	size_t x = file_length(file) - offset;
	// size_t x = strlen(file) - offset;
	
	size_t read_bytes;
	size_t zero_bytes;

	if(x < length){
		read_bytes = x;
		zero_bytes = pg_round_up(length) - read_bytes;
	}
	else{
		read_bytes = length;
		zero_bytes = pg_round_up(length) - read_bytes;
		// file은 10byte인데 3page 요청 들어오는 경우도 처리해야함
	}


	uint8_t *addr_iter = addr;
	void *addr_ret = addr;

	int num_page = 0; //for debug

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;


		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct informations *infos;
		infos = (struct informations *)malloc(sizeof(struct informations));
		infos->page_read_bytes = page_read_bytes;
		infos->page_zero_bytes = page_zero_bytes;
		infos->file = file;
		infos->ofs = offset;

		switch (num_page)
		{
		case 0:
			if (!vm_alloc_page_with_initializer (VM_FILE | VM_MARKER_1, addr_iter,
					writable, lazy_load_file_page, infos))
				return NULL;
			break;
		
		default:
			if (!vm_alloc_page_with_initializer (VM_FILE, addr_iter,
					writable, lazy_load_file_page, infos))
				return NULL; 
			break;
		}
		

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr_iter += PGSIZE;
		//mycode
		offset += page_read_bytes;

		num_page++;
	}

	
	return addr_ret; // 처음 address
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	// mmap시 여러 페이지가 할당되었다면, 
	// 가장 주소가 낮은 페이지는 VM_FILE | VM_MARKER_1로 마킹됨
	if (page->file.type != (VM_FILE | VM_MARKER_1) && page->uninit.type != (VM_FILE | VM_MARKER_1)) {
		return;
	}

	if (page->va != addr) {
		return;
	}

	uintptr_t addr_iter = addr;

	do {
		spt_remove_page(spt, page);
		addr_iter = addr_iter + PGSIZE;
		page = spt_find_page(spt, (void *)addr_iter);
		if (page == NULL) break;

	} while(page->file.type == VM_FILE || page->uninit.type == VM_FILE);
}

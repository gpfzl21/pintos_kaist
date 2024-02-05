/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

// our code
#include <hash.h>
#include "threads/mmu.h"


#define STACK_SIZE_MAX (1<<20)

struct hash frames;
struct lock frame_lock;
struct lock evict_lock;
struct hash_iterator frame_clock;

// struct hash swap_table;
struct lock swap_lock;

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, page_elem);
//   return hash_int (p->va);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, page_elem);
  const struct page *b = hash_entry (b_, struct page, page_elem);

  return a->va < b->va;
}

unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED) {
  const struct frame *f = hash_entry (f_, struct frame, frame_elem);
//   return hash_int(f->kva);
  return hash_bytes (&f->kva, sizeof f->kva);
}

bool
frame_less (const struct hash_elem *a_,
        	const struct hash_elem *b_, void *aux UNUSED) {
  const struct frame *a = hash_entry (a_, struct frame, frame_elem);
  const struct frame *b = hash_entry (b_, struct frame, frame_elem);

  return a->kva < b->kva;
}

// Find KVA from frames and return frame. On error, return NULL.
struct frame *
find_frame (void *kva UNUSED) {
	struct frame *frame = NULL;

	struct frame f;
	struct hash_elem *e;

	f.kva = pg_round_down(kva);
	e = hash_find (&frames, &f.frame_elem);
	if (e != NULL)
		frame = hash_entry(e, struct frame, frame_elem);

	return frame;
}

// Insert FRAME into frames with validation.
bool
insert_frame (struct frame *frame UNUSED) {
	int succ = false;

	lock_acquire(&frame_lock);

	// check existence of such kva of given frame
	struct frame *f = find_frame(frame->kva);
	if (f == NULL) {
		succ = true;
		hash_insert(&frames, &frame->frame_elem);
		hash_first (&frame_clock, &frames);
	}

	lock_release(&frame_lock);

	return succ;
}

// 프레임 구조체만 dealloc
void
vm_dealloc_frame (struct frame *frame) {
	lock_acquire(&frame_lock);

	struct hash_elem *e = hash_delete(&frames, &frame->frame_elem);
	if (e != NULL) {
		free(frame);
		hash_first (&frame_clock, &frames);
	}

	lock_release(&frame_lock);
}


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	hash_init(&frames, frame_hash, frame_less, NULL);
	lock_init(&frame_lock);
	lock_init(&evict_lock);
	hash_first(&frame_clock, &frames);
	
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
	
	if(is_kernel_vaddr(upage)) return false;

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = NULL;
		page = (struct page *)malloc(sizeof(struct page));

		bool (*initializer)(struct page *, enum vm_type, void *kva);

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initializer = &anon_initializer;
			break;
		case VM_FILE:
			initializer = &file_backed_initializer;
			break;
		default:
			PANIC("Unsuitable type input");
			break;
		}

		uninit_new(page, upage, init, type, aux, initializer);

		// You should modify the field after calling the uninit_new	
		page -> writable = writable;

		/* TODO: Insert the page into the spt. */
		struct thread *t = thread_current();
		if(!spt_insert_page(&t->spt, page)) {
			goto err;
		}

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page p;
	struct hash_elem *e;

	p.va = pg_round_down(va);
	e = hash_find (&spt->pages, &p.page_elem);
	if (e != NULL)
		page = hash_entry(e, struct page, page_elem);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	lock_acquire(&spt->page_lock);

	// check existence of such va of given page
	struct page *p = spt_find_page(spt, page->va);
	if (p == NULL) {
		succ = true;
		hash_insert(&spt->pages, &page->page_elem);
	}

	lock_release(&spt->page_lock);

	return succ;
}


bool
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	lock_acquire (&spt->page_lock);
	struct hash_elem *e = hash_delete(&spt->pages, &page->page_elem);

	if (e == NULL)
		return false;
	
	vm_dealloc_page (page);
	
	lock_release (&spt->page_lock);

	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	// clock 알고리즘 구현
	struct thread *t = thread_current();
	
	while (hash_next (&frame_clock)){
		victim = hash_entry(hash_cur(&frame_clock), struct frame, frame_elem);
		struct page *page = victim -> page;
		
		// 후에 page fault 났으면 표시해줄 것임.
		if (pml4_is_accessed(t->pml4, page->va)) {
			pml4_set_accessed(t->pml4, page->va, 0);
		} else {
			return victim;
		}
	}



	hash_first(&frame_clock, &frames);


	while (hash_next (&frame_clock)) {
		victim = hash_entry(hash_cur(&frame_clock), struct frame, frame_elem);
		struct page *page = victim -> page;
		if (pml4_is_accessed(t->pml4, page->va)) {
			pml4_set_accessed(t->pml4, page->va, 0);
		} else {
			return victim;
		}
	}


	hash_first(&frame_clock, &frames);


	while (hash_next (&frame_clock)) {
		victim = hash_entry(hash_cur(&frame_clock), struct frame, frame_elem);
		struct page *page = victim -> page;
		
		// 후에 page fault 났으면 표시해줄 것임.
		if (pml4_is_accessed(t->pml4, page->va)) {
			pml4_set_accessed(t->pml4, page->va, 0);
		} else {
			return victim;
		}
	}

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	lock_acquire(&evict_lock);
	struct frame *victim UNUSED = vm_get_victim ();

	/* TODO: swap out the victim and return the evicted frame. */
	// 동기화좀 잘해주기 - 두 번 acquire 주의
	struct page *page = victim->page;
	swap_out(page);
	pml4_clear_page(thread_current()->pml4, page->va);
	page->frame = NULL;
	victim->page = NULL;

	lock_release(&evict_lock);
	
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
	// printf("get frame with kva %p\n", kva);	// for debug
	if (kva == NULL) {
		frame = vm_evict_frame();
		memset(frame->kva, 0, PGSIZE);
	} else {
		frame = (struct frame *)malloc(sizeof(struct frame));
		frame -> kva = kva;
		frame -> page = NULL;
		ASSERT(insert_frame(frame));
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	addr = pg_round_down(addr);

	while(addr < (spt->stack_bottom)) {
		spt->stack_bottom = (void *) (((uint8_t *) spt->stack_bottom) - PGSIZE);
		ASSERT(vm_alloc_page(VM_ANON | VM_MARKER_0, spt->stack_bottom, true));
		ASSERT(vm_claim_page(spt->stack_bottom));
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

// our code: stack growth 가능여부
static bool
vm_valid_stack_growth (uintptr_t addr UNUSED, uintptr_t rsp UNUSED) {
	bool address_in_range = (addr < USER_STACK) && (addr > (USER_STACK - STACK_SIZE_MAX));
	bool address_with_rsp = (addr >= rsp - 8);
	return address_in_range && address_with_rsp;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// printf("vm_try_handle_fault start\n");
	// printf("addr: %p\n", addr);
	// printf("not_present: %d\n", not_present);
	// printf("user: %d\n", user);
	// printf("write: %d\n", write);
	// printf("rsp: %p\n", f->rsp);
	// printf("rip: %p\n", f->rip);

	if (!not_present) {
		exit(-1);
		return false;
	}


	if (is_kernel_vaddr(addr)) {
		exit(-1);
		return false;
	}

	page = spt_find_page(spt, addr);

	if (page == NULL) {
		if (vm_valid_stack_growth(addr, f->rsp)){
			vm_stack_growth(addr);
			return true;
		}

		exit(-1);
		return false;
	}


	bool x = vm_do_claim_page(page);
	page = spt_find_page(spt, addr);


	if (x) {
		pml4_set_accessed(thread_current()->pml4, page->va, 1);
	}
	return x;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	struct thread *t = thread_current();
	page = spt_find_page(&t->spt, va);
	if (page == NULL) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *t = thread_current();
	if (!pml4_set_page(t->pml4, page->va, frame->kva, page->writable)) {
		vm_dealloc_frame(frame);
	}

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->pages, page_hash, page_less, NULL);
	lock_init(&spt->page_lock);
	spt->stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
	// stack 주소를 복사해주자
	dst->stack_bottom = src->stack_bottom;
	lock_init(&dst->page_lock);


	struct hash_iterator i;
	hash_first (&i, &src->pages);

	while (hash_next (&i)) {
		struct page *src_page = hash_entry (hash_cur (&i), struct page, page_elem);
		struct page *dst_page = (struct page *)malloc(sizeof(struct page));

		// swap out 되어있으면, claim을 해라!

		// 복사본 만들기
		// page 자체(frame은 복사본 가르켜야함. va도..) + frame(get_frame 한다음 정보 바꾸면 될라나)
		struct frame *dst_frame = vm_get_frame(); // insert_frame도 같이 수행

		memcpy(dst_page, src_page, sizeof(struct page));
		memcpy(dst_frame->kva, src_page->frame->kva, PGSIZE);
		dst_page -> frame = dst_frame;
		dst_frame -> page = dst_page;

		if (!spt_insert_page(dst, dst_page)) {
			return false;
		}

		if (VM_TYPE (dst_page->operations->type) != VM_UNINIT) {
			if (!pml4_set_page (thread_current()->pml4, dst_page->va, dst_frame->kva, dst_page->writable)) {
				return false;
			}
		}
		else {
			vm_do_claim_page(dst_page);
		}
		
	}

	return true;
}


void
spt_destructor (struct hash_elem *e, void* aux){
	ASSERT(e != NULL);
	struct page *page = hash_entry(e, struct page, page_elem);
	struct frame *frame = page->frame;
	destroy(page);
	free(page);
	if (frame != NULL) {
		vm_dealloc_frame(frame);
	}
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. called by exit*/

	struct hash_iterator i;
	hash_first (&i, &spt->pages);

	// ver 2
	struct hash_elem *e = hash_next (&i);
	struct page *page = hash_entry (hash_cur (&i), struct page, page_elem);
	while (true) {
		if (e == NULL) break;
		struct frame *frame = page->frame;
		e = hash_next (&i);
		struct page *next = hash_entry (hash_cur (&i), struct page, page_elem);
		destroy(page);
		free(page);
		if (frame != NULL) {
			vm_dealloc_frame(frame);
		}
		page = next;
	}

	supplemental_page_table_init(spt);
}


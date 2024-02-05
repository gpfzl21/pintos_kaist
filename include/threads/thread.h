#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif

#include "filesys/file.h"
#include "threads/synch.h"

// #include "filesys/directory.c"
#include "filesys/directory.h"

/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */
#define NICE_DEFAULT 0					/* default nice value*/
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

// for file
#define OPEN_MAX 128

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

// struct wait_stat{
// 	tid_t tid;
// 	bool is_wait;
// 	struct list_elem wait_elem;
// }

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	int64_t wakeup_tick; // store the tick to wake up!!

	/*
	 *  for priority donation
	 */	
	// store priority before donation
	int pre_priority;
	// lock that the thread want
	struct lock *waiting_lock;
	// store donators
	struct list donations_list;
	// in donation list
	struct list_elem donation_elem;

	/*
	 *   for MLFQ
	 */
	int32_t nice;
	int32_t recent_cpu;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */

	// our code

	// exit status when call exit system call
	int exit_status;
	// whether load success
	bool load_status;
	// whether process terminate
	bool terminate_status;
	// wait semaphore - when current thread system calls wait, it waits by sema down of child
	struct semaphore wait_sema; 
	// delay break relationship between current thread and parent when call exit
	struct semaphore delay_break_sema; 
	// parent pcb
	struct thread *parent_thread;
	
	// child list
	struct list child_list;
	// to put in child list and use list_entry
	struct list_elem child_elem;

	// for fork
	struct semaphore fork_sema;
	struct intr_frame *for_fork_if;
	
	/*
	 * for file
	 */
	struct list fd_table;
	int next_fd;
	struct file *exec_file;

	/* Note below file struct
	 * struct file 
	 * struct inode *inode;  File's inode.
	 * off_t pos;            Current position
	 * bool deny_write;      Has file_deny_write() been called?
	 */


#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
	
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */

	// for project 4
	struct dir *curr_dir;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);


/*
 *  functions we added            
 */

// for alarm clock
void update_next_wakeup_tick(int64_t new_ticks);
int64_t get_next_wakeup_tick(void);
void go_sleep_thread(int64_t ticks);
void wakeup_thread(int64_t ticks);

// for priority schedule
bool compare_p_prior_to_q(const struct list_elem *p, const struct list_elem *q, void *aux UNUSED);
void yield_according_to_priority (void);

// for priority donation
void donate_priority (void); 
void update_priority(void); 
void remove_donation_related_to_lock(struct lock *lock);

// for mlvqs
int thread_get_nice (void);
void thread_set_nice (int nice);
int32_t thread_get_recent_cpu (void);
int32_t thread_get_load_avg (void);

void mlfqs_update_priority (struct thread *t); //when mlfqs, update priority
void mlfqs_update_recent_cpu (struct thread *t); //when mlfqs, update recent cpu
void mlfqs_update_load_avg(void); //when mlfqs, update load avg
void mlfqs_recent_cpu_increment(void); //increase recent cpu for every tick
void mlfqs_update_all_recent_cpu(void); //update recent_cpu of every thread
void mlfqs_update_all_priority(void); //update priority of every thread


#endif /* threads/thread.h */

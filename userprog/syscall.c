#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include <lib/stdio.h>
#include <kernel/stdio.h>
#include "kernel/list.h"
#include "threads/malloc.h"
#include "filesys/inode.h"

#include "vm/vm.h"

// project 4
#include "filesys/directory.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */


// project 2

void valid_check(const void* x){
	if (is_kernel_vaddr(x))
		exit(-1);
}


struct semaphore file_sema;


// make file_s
struct file_s *init_file_s(struct file *f, int fd){
	struct file_s *new_one = (struct file_s *) malloc(sizeof(struct file_s));
	new_one->file = f;
	new_one->fd = fd;
	
	return new_one;
}

// Find file via fd value
struct file *
find_file (int find_fd, struct list *fd_table) {

	if(find_fd < 0) return NULL;
	struct list_elem *e;
	e = list_begin(fd_table);
	while (e != list_end(fd_table)) {
		
		int e_fd = list_entry(e, struct file_s, fd_elem) -> fd;
		if (e_fd == find_fd)
			return list_entry(e, struct file_s, fd_elem) -> file;
		e = list_next(e);
	}
	return NULL;
}

struct file_s *
find_file_s (int find_fd, struct list *fd_table) {
	if(find_fd < 0) return NULL;
	struct list_elem *e;
	e = list_begin(fd_table);
	while (e != list_end(fd_table)) {
		int e_fd = list_entry(e, struct file_s, fd_elem) -> fd;
		if (e_fd == find_fd)
			return list_entry(e, struct file_s, fd_elem);
		e = list_next(e);
	}
	return NULL;
}


// project 3
void valid_buffer (void *buffer, unsigned size, bool from_read) {
	struct supplemental_page_table *spt = &thread_current()->spt;

	void *iter_buffer = buffer;
	while (iter_buffer < (buffer + size)) {
		struct page *page = spt_find_page(spt, iter_buffer);
		if (page == NULL) {
			exit(-1);
		}
		if ((!page->writable) && from_read) {
			exit(-1);
		}
		iter_buffer += PGSIZE;
	}
}

void
syscall_init (void) {
	// our code: init file_lock
	sema_init(&file_sema, 1);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface 
 * syscall.h : For user program only
 * system call number : %rax, 
 * arguments : %rdi, %rsi, %rdx, %r10, %r8, and %r9. 
*/
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	// check validity of user pointer
	if (f->R.rax == SYS_HALT)
		halt();
	else {
		uint64_t first_var = f->R.rdi; // copy to keep from TOCTOU attack
		uint64_t second_var = f->R.rsi; // copy to keep from TOCTOU attack
		uint64_t third_var = f->R.rdx; // copy to keep from TOCTOU attack
		uint64_t fourth_var = f->R.r10; // copy to keep from TOCTOU attack
		uint64_t fifth_var = f->R.r8; // copy to keep from TOCTOU attack
			
		switch (f->R.rax)
		{
		case SYS_EXIT:
			valid_check(first_var);
			exit(first_var);
			break;
		case SYS_FORK:
			valid_check(first_var);
			thread_current()->for_fork_if = f;
			f->R.rax = fork(first_var);
			break;
		case SYS_EXEC:
			valid_check(first_var);
			f->R.rax = exec(first_var);
			break;
		case SYS_WAIT:
			valid_check(first_var);
			f->R.rax = wait(first_var);
			break;
		case SYS_CREATE:
			valid_check(first_var);
			valid_check(second_var);
			f->R.rax = create(first_var, second_var);
			break;
		case SYS_REMOVE:
			valid_check(first_var);
			f->R.rax = remove(first_var);
			break;
		case SYS_OPEN:
			valid_check(first_var);
			f->R.rax = open(first_var);
			break;
		case SYS_FILESIZE:
			valid_check(first_var);
			f->R.rax = filesize(first_var);
			break;
		case SYS_READ:
			valid_check(first_var);
			valid_check(second_var);
			valid_check(third_var);
			f->R.rax = read(first_var, second_var , third_var);
			break;
		case SYS_WRITE:
			valid_check(first_var);
			valid_check(second_var);
			valid_check(third_var);
			f->R.rax = write(first_var, second_var, third_var);
			break;
		case SYS_SEEK:
			valid_check(first_var);
			valid_check(second_var);
			seek(first_var, second_var);
			break;
		case SYS_TELL:
			valid_check(first_var);
			f->R.rax = tell(first_var);
			break;
		case SYS_CLOSE:
			valid_check(first_var);
			close (first_var);
			break;
		case SYS_MMAP:
			f->R.rax = mmap (first_var, second_var, third_var, fourth_var, fifth_var);
			break;
		case SYS_MUNMAP:
			valid_check(first_var);
			munmap (first_var);
			break;
		case SYS_CHDIR:
			valid_check(first_var);
			f->R.rax = chdir (first_var);
			break;
		case SYS_MKDIR:
			valid_check(first_var);
			f->R.rax = mkdir (first_var);
			break;
		case SYS_READDIR:
			valid_check(first_var);
			valid_check(second_var);
			f->R.rax = readdir (first_var, second_var);
			break;
		case SYS_ISDIR:
			valid_check(first_var);
			f->R.rax = isdir (first_var);
			break;
		case SYS_INUMBER:
			valid_check(first_var);
			f->R.rax = inumber (first_var);
			break;
		case SYS_SYMLINK:
			valid_check(first_var);
			valid_check(second_var);
			f->R.rax = symlink(first_var, second_var);
			break;
		default:
			thread_exit();
			break;
		}
	}
	
}


/*
 * our code: system call
 */
void halt (void) {
	printf("halt\n");
	power_off();
}

void exit (int status){
	struct thread *curr = thread_current();
	printf ("%s: exit(%d)\n", thread_name (), status);
	curr->exit_status = status;
	thread_exit();
}


pid_t fork (const char *thread_name){

	struct thread *curr = thread_current();

	int depth_count = 0;
	struct thread *parent = curr -> parent_thread;
	while (parent != NULL) {
		depth_count++;
		parent = parent -> parent_thread;
	}
	if (depth_count > 30) exit(depth_count);

	tid_t child_pid = process_fork(thread_name, curr->for_fork_if);

	// if child fork worked well, then lock release
	sema_down(&curr->fork_sema);
	
	return child_pid;
}

int exec (const char *cmd_line) {

	sema_down(&file_sema);

	char *fn_copy;
	struct thread *t = thread_current();


	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL) {
		sema_up(&file_sema);
		return TID_ERROR;
	}
	strlcpy (fn_copy, cmd_line, PGSIZE);
	
	int ret = process_exec(fn_copy); // 내부에서 sema_up(&file_sema) 수행

	return ret;
}

int wait (pid_t pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
	if(file == NULL) {
		exit(-1);
	}

	bool crfile = filesys_create(file, initial_size);

	return crfile;
}

bool remove (const char *file) {
	bool rmfile;
	if (!strcmp(file, "/")) {
		rmfile = false;
	} else {
		struct dir *curr_dir = thread_current()->curr_dir;
		struct inode *curr_dir_inode = dir_get_inode(curr_dir);
		struct file *f = filesys_open(file);

		if (inode_is_dir(f->inode)) {
			if (curr_dir_inode == f->inode) {
				rmfile = false;
			} else if (inode_open_count( f->inode ) > 1) {
				rmfile = false;
			} else {
				rmfile = filesys_remove (file);
			}
		} else {
			rmfile = filesys_remove (file);
		}
		file_close(f);
	}
	return rmfile;
}

int open (const char *file) {
	struct thread *curr = thread_current();
	
	if(file == NULL) exit(-1);

	struct file *opened_file = filesys_open(file);
	
	if(opened_file == NULL) {
		return -1;
	}
	else {
		curr->next_fd++;
		struct file_s *new = init_file_s(opened_file, curr->next_fd);
		list_push_back(&curr->fd_table, &new->fd_elem);
		struct inode *inode = opened_file->inode;
		return curr->next_fd;
	}

}

int filesize (int fd) {
	int size;

	struct thread *curr = thread_current();
	struct file *f = find_file(fd, &curr->fd_table);
	if(f == NULL) size = -1;
	else size = file_length(f);

	return size;
}

int read (int fd, void *buffer, unsigned size) {
	valid_buffer(buffer, size, true);

	int read_bytes;

	if (fd == STDIN_FILENO) read_bytes = input_getc();
	else {
		struct thread *curr = thread_current();
		struct file *f = find_file(fd, &curr->fd_table);
		if(f == NULL) read_bytes = -1;
		else read_bytes = file_read(f, buffer, size);
	}

	return read_bytes;
}

int write (int fd, const void *buffer, unsigned size){
	valid_buffer(buffer, size, false);
	if(buffer == NULL) exit(-1);

	if(isdir(fd)) {
		return -1;
	}

	int write_bytes;
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		write_bytes = size;
	}  
	else{
		struct thread *curr = thread_current();
		struct file *f = find_file(fd, &curr->fd_table);

		if(f == NULL) write_bytes = -1;
		else{
			write_bytes = file_write(f, buffer, (off_t)size);
		}

	}
	return write_bytes;
}

void seek (int fd, unsigned position) {
	struct thread *curr = thread_current();
	struct file* f = find_file(fd, &curr->fd_table);
	if (f != NULL) file_seek(f, position);
}

unsigned tell (int fd) {
	int ret;
	struct file *f = find_file(fd, &thread_current()->fd_table) ;
	if (f != NULL) ret = file_tell(f);
	return ret;
}


void close (int fd){
	struct thread *curr = thread_current();
	struct file_s *f_s = find_file_s(fd, &curr->fd_table);
	if (f_s != NULL) {
		file_close(f_s->file);
		list_remove(&f_s->fd_elem);
	}
}

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	struct thread *t = thread_current(); //for debug

	if (is_kernel_vaddr(addr)) {
		return NULL;
	}

	// - file descriptor(fd)가 콘솔 input/output 용이라면 그것도 not mappable
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
		return NULL;
	}

	// - fd로 열린 file이 length of zero byte일때 return null
	int file_size = filesize(fd);
	if (file_size == 0) {
		return NULL;
	}

	// - addr이 page-aligned 되어있지 않아도 return null
	if ((uintptr_t)addr % PGSIZE != 0) {
		return NULL;
	}

	// - parameter에서 주소로 0이 들어왔다면  return null
	if ((uintptr_t)addr == 0) {
		return NULL;
	}

	// - parameter에서 length가 0이면 return null
	if (length == 0)	{
		return NULL;
	}

	// - offset 또한 multiple of the page size as returned by sysconf(_SC_PAGE_SIZE).
	if (offset % PGSIZE != 0) {
		return NULL;
	}

	struct file *f = find_file(fd, &thread_current()->fd_table);
	
	struct file *file = file_reopen(f);

	if(file_size < offset) {
		return NULL;
	}

	return do_mmap(addr, length, writable, file, offset); 
}

void munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *p = spt_find_page(spt, addr);

	ASSERT(p != NULL);

	if (VM_TYPE(p->operations->type) != VM_FILE) {
		return;
	}

	do_munmap (addr);
}

bool chdir (const char *dir) {
	struct thread *t = thread_current();

	char *file_name = (char *)malloc(sizeof(char) * 16);
	struct dir *ahead_dir = path_to_dir(dir, file_name);

	// 주어진 path가 루트 디렉토리인 경우
	if(!strcmp(file_name, "/")) {
		dir_close(t->curr_dir);
		t->curr_dir = ahead_dir;
		free(file_name);
		return true;
	}

	struct inode *inode;

	if (!dir_lookup(ahead_dir, file_name, &inode)) {
		dir_close(ahead_dir);
		free(file_name);
		return false;
	}

	if(!inode_is_dir(inode)) {
		inode_close(inode);
		dir_close(ahead_dir);
		free(file_name);
		return false;
	}

	struct dir *real_dir = dir_open(inode);

	dir_close(t->curr_dir);
	t->curr_dir = real_dir;

	dir_close(ahead_dir);

	free(file_name);
	return true;
}

bool mkdir (const char *dir) {
	return filesys_mkdir(dir);
}

bool readdir (int fd, char *name) {
	if (!isdir (fd)) return false;
	struct file *f = find_file(fd, &thread_current()->fd_table);
	if(f == NULL) return false;

	struct dir *dir = (struct dir *)malloc(sizeof_dir_struct());
	memcpy(dir, f, sizeof_dir_struct());
	if (f->pos == 0) {
		dir_readdir(dir, name); // . 읽어옴
		dir_readdir(dir, name); // .. 읽어옴
	}
	bool success = dir_readdir(dir, name);
	f->pos = dir_get_pos(dir);
	free(dir);
	
	return success;
}

bool isdir (int fd) {
	struct file *f = find_file(fd, &thread_current()->fd_table);
	if (f == NULL) return false;
	return inode_is_dir(file_get_inode(f));
}

int inumber (int fd) {
	struct file *f = find_file(fd, &thread_current()->fd_table);
	if (f == NULL) return 0;
	return inode_get_inumber(file_get_inode(f));
}

int symlink (const char *target, const char *linkpath){
	// retrun 0 on success, return -1 on failure
	if (filesys_symlink(target, linkpath))
		return 0;
	else 
		return -1;
}

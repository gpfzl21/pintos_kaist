#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>


#include "filesys/file.h"
#include <list.h>
#include "threads/thread.h"


/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int off_t;
#define MAP_FAILED ((void *) NULL)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */



void syscall_init (void);


/* Projects 2 and later. */
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int dup2(int oldfd, int newfd);

// for project 3
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

// for project 4
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
int symlink (const char *target, const char *linkpath);

// our defined funct
struct file *find_file(int find_fd, struct list *fd_table);
struct file_s *find_file_s(int find_fd, struct list *fd_table);
struct file_s *init_file_s(struct file *f, int fd);

struct file_s {
	struct list_elem fd_elem;
	struct file *file;
	int fd;
	
};

struct file {
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. indicate next offset 
									into file to read or write*/
	bool deny_write;            /* Has file_deny_write() been called? */
};


#endif /* userprog/syscall.h */

#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

// our code
#include "filesys/fat.h"
#include "threads/thread.h"

/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry), 1, 0);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}


/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
	struct dir *root_dir;
#ifdef EFILESYS
	root_dir = dir_open (inode_open (cluster_to_sector(ROOT_DIR_CLUSTER)));
#else
	root_dir = dir_open (inode_open (ROOT_DIR_SECTOR));
#endif
	root_dir;
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if(!strcmp(name, ".") || !strcmp(name,".."))
		goto done;

	/* Find directory entry. */
	if (!lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	// 디렉토리 엔트리가 디렉토리고, 거기에다가 항까지 있으면 터뜨림
	struct dir *entry_dir = NULL;
	if (inode_is_dir(inode)) {
		entry_dir = dir_open(inode);

		struct dir_entry f;
		off_t offs;

		for (offs = 0; inode_read_at (entry_dir->inode, &f, sizeof f, offs) ==
			 sizeof f; offs += sizeof f) {
				 // 이용중인게 있으면 터지는데, 단 .과 ..은 예외
			if (f.in_use && strcmp(f.name, ".") && strcmp(f.name,"..")) {
				dir_close(entry_dir);
				goto done;
			}
		}
	}

	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	if (entry_dir != NULL) {
		dir_close(entry_dir);
	} else {
		inode_close(inode);
	}
	success = true;

done:
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}

struct dir*
path_to_dir (char *path_name, char *file_name) {

	struct dir *dir;
	if (strlen(path_name) == 0) {
		return NULL;
	}
	if (path_name == NULL) {
		return NULL;
	}
	// determine root or not
	if (path_name[0] == '/') {
		dir = dir_open_root();
	} else {
		dir = dir_reopen(thread_current()->curr_dir);
	}

	char *path_name_copy = palloc_get_page(0);
	if (path_name_copy == NULL)
		return TID_ERROR;
	strlcpy(path_name_copy, path_name, 1 << 12);

	char *p;
	char *next_p;
	char *temp_p;

	p = strtok_r(path_name_copy, "/", &temp_p);
	next_p = strtok_r(NULL, "/", &temp_p);

	// 사용자가 디렉토리처럼 a/b 같이 쓴 경우
	while (p != NULL && next_p != NULL) {
		struct inode *inode = NULL;

		// 애초에 디렉토리에 없는걸 적은 경우
		if (!dir_lookup(dir, p, &inode)) {
			goto inval;
		}

		// /a/b/c/d에서 c가 파일도 symbolic link도 아닌 경우
		if (!inode_is_dir(inode) && !inode_is_sym(inode)) {
			goto inval;
		}

		while (inode_is_sym(inode)) {
			char *temp_name = malloc(NAME_MAX + 1);
			inode_read_at(inode, temp_name, NAME_MAX + 1, 0);
			disk_sector_t temp_dir_sec;
			inode_read_at(inode, &temp_dir_sec, sizeof(temp_dir_sec), 16);
			struct inode *temp_dir_inode = inode_open(temp_dir_sec);
			struct dir *temp_dir = dir_open(temp_dir_inode);

			struct inode *sym_inode = NULL;
			if (!dir_lookup(temp_dir, temp_name, &sym_inode)) {
				dir_close(temp_dir);
				free(temp_name);
				inode_close(inode);
				return NULL;
			}
			dir_close(temp_dir);
			free(temp_name);
			inode_close(inode);
			
			inode = sym_inode;
		}

		if (!inode_is_dir(inode)) {
			inode_close(inode);
			goto inval;
		}

		dir_close(dir);
		dir = dir_open(inode);

		p = next_p;
		next_p = strtok_r(NULL, "/", &temp_p);
	}

	if (p == NULL) {
		strlcpy(file_name, "/", 2);
		palloc_free_page(path_name_copy);
		return dir;
	}

	if (strlen(p) > NAME_MAX) {
		goto inval;
	}
	

	strlcpy(file_name, p, strlen(p) + 1);

	palloc_free_page(path_name_copy);

	return dir;

inval:
	dir_close(dir);
	palloc_free_page(path_name_copy);
	return NULL;
}

size_t 
sizeof_dir_struct(void) {
	return sizeof(struct dir);
}

int32_t 
dir_get_pos(struct dir *dir) {
	return dir->pos;
}
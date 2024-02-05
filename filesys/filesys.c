#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

// our code
#include "filesys/fat.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
	thread_current()->curr_dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;

	char *file_name = (char *)malloc(NAME_MAX + 1);
	if (file_name == NULL)
		return TID_ERROR;

	// file_name에 진짜 파일 네임 넣어주고 dir 뽑아내기
	struct dir *dir = path_to_dir(name, file_name);


#ifdef EFILESYS
	cluster_t inode_clst = 0;
	bool success = (dir != NULL
			&& (inode_clst = fat_create_chain(0)) != 0
			&& inode_create (cluster_to_sector(inode_clst), initial_size, 0, 0)
			&& dir_add (dir, file_name, cluster_to_sector(inode_clst)));
	if (!success && inode_clst)
		fat_remove_chain (inode_clst, 0);
#else
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size, 0, 0)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
#endif
	dir_close (dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	if (!strcmp(name, "/")) {
		struct dir *dir = dir_open_root();
		struct inode *inode = dir_get_inode(dir);
		return file_open(inode);
	}

	char *file_name = (char *)malloc(sizeof(char) * 16);
	if (file_name == NULL)
		return NULL;

	// file_name에 진짜 파일 네임 넣어주고 dir 뽑아내기
	struct dir *dir = path_to_dir(name, file_name);
	if (!strcmp(file_name, "/")) {
		free(file_name);
		return file_open(dir_get_inode(dir));
	}

	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, file_name, &inode);
	dir_close (dir);

	free(file_name);

	if(inode == NULL) return NULL;

	// file_name인 것이 symlink인 경우
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

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	char *file_name = (char *)malloc(sizeof(char) * 16);
	if (file_name == NULL)
		return TID_ERROR;

	// file_name에 진짜 파일 네임 넣어주고 dir 뽑아내기
	struct dir *dir = path_to_dir(name, file_name);

	bool success = dir != NULL && dir_remove (dir, file_name);

	dir_close(dir);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	if (!dir_create (cluster_to_sector(ROOT_DIR_CLUSTER), 16))
		PANIC ("root directory creation failed\n");
	struct dir *root_dir = dir_open_root();
	if (!dir_add(root_dir, ".", cluster_to_sector(ROOT_DIR_CLUSTER))) {
		PANIC ("root directory creation failed 2\n");
	}
	if (!dir_add(root_dir, "..", cluster_to_sector(ROOT_DIR_CLUSTER))) {
		PANIC ("root directory creation failed 3\n");
	}
	dir_close(root_dir);
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

// our code: make directory
bool filesys_mkdir(const char *path) {
	if (!strcmp(path, "")) {
		return false;
	}

	char *dir_file_name = (char *)malloc(sizeof(char) * 15);
	struct dir *dir = path_to_dir(path, dir_file_name);

	// Empty path
	if (!strcmp(dir_file_name, "")) {
		dir_close(dir);
		free(dir_file_name);
		return false;
	}

	cluster_t clst = fat_create_chain(0);

	if (clst == 0) {
		dir_close(dir);
		free(dir_file_name);
		return false;
	}

	// free sector는 dir를 만들 디스크 섹터
	disk_sector_t free_sector = cluster_to_sector(clst);
	if (!dir_create (free_sector, 16)) {
		goto err;
	}


	// dir에 dir_file_name -> free_sector로의 매핑 추가
	if (!dir_add(dir, dir_file_name, free_sector)) {
		goto err;
	}


	struct inode *inode = inode_open(free_sector);

	// dir_file로 우리가 만든 디렉토리 열어줌
	struct dir *dir_file = dir_open(inode);
	if (dir_file == NULL) {
		goto err;
	}
	
	if (!dir_add(dir_file, ".", free_sector)) {
		dir_close(dir_file);
		dir_remove(dir, dir_file_name);
		goto err;
	}
	
	if (!dir_add(dir_file, "..", inode_get_inumber(dir_get_inode(dir)))) {
		dir_close(dir_file);
		dir_remove(dir, dir_file_name);
		goto err;
	}

	dir_close(dir_file);
	dir_close(dir);
	return true;

err:
	fat_remove_chain(clst, 0);
	dir_close(dir);
	free(dir_file_name);
	return false;
	
}

bool filesys_symlink(const char *target, const char *linkpath) {
	// filename is linkpath, contain target

	char *file_name = (char *)malloc(NAME_MAX + 1);
	if (file_name == NULL)
		return false;

	char *target_file_name = (char *)malloc(NAME_MAX + 1);
	if (target_file_name == NULL)
		return false;

	// file_name에 진짜 파일 네임 넣어주고 dir 뽑아내기
	struct dir *dir = path_to_dir(linkpath, file_name);
	struct dir *target_dir = path_to_dir(target, target_file_name);
	
	// file_name | sector_addr
    //          16
	// 위와 같은 형태로 쓰기
	cluster_t inode_clst;
	bool success = (dir != NULL
			&& (inode_clst = fat_create_chain(0)) != 0
			&& inode_create (cluster_to_sector(inode_clst), strlen(target), 0, 1)
			&& dir_add (dir, file_name, cluster_to_sector(inode_clst)));
	if (!success) {
		fat_remove_chain(inode_clst, 0);
	} else {
		struct inode *inode = inode_open(cluster_to_sector(inode_clst));
		disk_sector_t target_dir_sector
			= inode_get_inumber( dir_get_inode(target_dir) );
		if (!inode_write_at(inode, target_file_name, NAME_MAX + 1, 0) ||
			!inode_write_at(inode, &target_dir_sector, sizeof(target_dir_sector), 16)) {
			dir_remove(dir, file_name);
			fat_remove_chain (inode_clst, 0);
			success = false;
		}
	}

	dir_close(target_dir);
	dir_close(dir);
	return success;
}
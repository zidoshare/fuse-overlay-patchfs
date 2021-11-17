/* fuse-overlayfs: Overlay Filesystem in Userspace

   Copyright (C) 2019 Red Hat Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef UTILS_H
# define UTILS_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

# include <config.h>

# include <unistd.h>
# include <stdio.h>
# include <sys/types.h>
# include <dirent.h>
# include <stdlib.h>
# include <sys/types.h>
# include <fcntl.h>
# include "fuse-overlayfs.h"
# include <sys/file.h>

# define XATTR_OVERRIDE_STAT "user.fuseoverlayfs.override_stat"
# define XATTR_PRIVILEGED_OVERRIDE_STAT "security.fuseoverlayfs.override_stat"
# define XATTR_OVERRIDE_CONTAINERS_STAT "user.containers.override_stat"

void cleanup_freep (void *p);
void cleanup_filep (FILE **f);
void cleanup_closep (void *p);
void cleanup_dirp (DIR **p);

int file_exists_at (int dirfd, const char *pathname);

int strconcat3 (char *dest, size_t size, const char *s1, const char *s2, const char *s3);
int open_fd_or_get_path (struct ovl_layer *l, const char *path, char *out, int *fd, int flags);

# define cleanup_file __attribute__((cleanup (cleanup_filep)))
# define cleanup_free __attribute__((cleanup (cleanup_freep)))
# define cleanup_close __attribute__((cleanup (cleanup_closep)))
# define cleanup_dir __attribute__((cleanup (cleanup_dirp)))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

# ifdef HAVE_STATX
void statx_to_stat (struct statx *stx, struct stat *st);
# endif

int safe_openat (int dirfd, const char *pathname, int flags, mode_t mode);

int override_mode (struct ovl_layer *l, int fd, const char *abs_path, const char *path, struct stat *st);

enum units {
    BYTES = 1L,
    KILOBYTES = 1024L,
    MEGABYTES = 1048576L,
    GIGABYTES = 1073741824L,
    TERABYTES = 1099511627776L
};

enum units char_to_units(const char c);

int quota_set(const char *path, unsigned long size, enum units unit);

long double quota_get(const char *path, enum units unit);

long incr_size(const char *path, long s);

long quota_exceeded(const char *path);

void quota_unset(const char *path);

int limited(const char *path);

#define BYTES_IN_KILOBYTE 1024.0L
#define BYTES_IN_MEGABYTE 1048576.0L
#define BYTES_IN_GIGABYTE 1073741824.0L
#define BYTES_IN_TERABYTE 1099511627776.0L

long entry_size(const char *path);

ssize_t space(const char *path);

// 初始化
void local_xattr_db_init(const char* db_parent_path);

void local_xattr_db_release();


int local_set_xattr(ino_t ino, const char *name, const void *value,
	 size_t size, int flags);

int ulsetxattr(const char* path,
           const char* name,
           const char* value,
           size_t size,
           int flags);

int ufsetxattr(int fd, const char *name,
                  const void *value, size_t size, int flags);

int usetxattr(const char* path,
           const char* name,
           const char* value,
           size_t size,
           int flags);

ssize_t ufgetxattr(int fd, const char *name,
                  void *value, size_t size);

ssize_t ulgetxattr(const char* path, const char* name, char* value, size_t size);

ssize_t ugetxattr(const char* path, const char* name, char* value, size_t size);

ssize_t uflistxattr(int fd, char *list, size_t size);

ssize_t ullistxattr(const char* path, char* list, size_t size);

ssize_t ulistxattr(const char* path, char* list, size_t size);

int ufremovexattr(int fd, const char *name);

int uremovexattr(const char* path, const char* name);

int ulremovexattr(const char* path, const char* name);

#endif

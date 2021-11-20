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

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <config.h>
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdatomic.h>
#include <limits.h>
#include <sys/statfs.h>
#include <pthread.h>
#include <leveldb/c.h>
#include <fcntl.h>

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif

#ifndef RESOLVE_IN_ROOT
# define RESOLVE_IN_ROOT		0x10
#endif
#ifndef __NR_openat2
# define __NR_openat2 437
#endif

/* uClibc and uClibc-ng don't provide O_TMPFILE */
#ifndef O_TMPFILE
# define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

/* List of all valid flags for the open/openat flags argument: */
#define VALID_OPEN_FLAGS \
  (O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
   O_APPEND | O_NDELAY | O_NONBLOCK | O_NDELAY | O_SYNC | O_DSYNC |     \
   FASYNC | O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW |         \
   O_NOATIME | O_CLOEXEC | O_PATH | O_TMPFILE)

static int
syscall_openat2 (int dirfd, const char *path, uint64_t flags, uint64_t mode, uint64_t resolve)
{
  struct openat2_open_how
    {
      uint64_t flags;
      uint64_t mode;
      uint64_t resolve;
    }
  how =
    {
     .flags = flags & VALID_OPEN_FLAGS,
     .mode = (flags & O_CREAT) ? (mode & 07777) : 0,
     .resolve = resolve,
    };

  return (int) syscall (__NR_openat2, dirfd, path, &how, sizeof (how), 0);
}

int
safe_openat (int dirfd, const char *pathname, int flags, mode_t mode)
{
  static bool openat2_supported = true;

  if (openat2_supported)
    {
      int ret;

      ret = syscall_openat2 (dirfd, pathname, flags, mode, RESOLVE_IN_ROOT);
      if (ret < 0)
        {
          if (errno == ENOSYS)
            openat2_supported = false;
          if (errno == ENOSYS || errno == EINVAL)
            goto fallback;
        }
      return ret;
    }
 fallback:
  return openat (dirfd, pathname, flags, mode);
}

int
file_exists_at (int dirfd, const char *pathname)
{
  int ret = faccessat (dirfd, pathname, F_OK, AT_SYMLINK_NOFOLLOW|AT_EACCESS);
  if (ret < 0 && errno == EINVAL) {
    struct stat buf;
    return fstatat (dirfd, pathname, &buf, AT_SYMLINK_NOFOLLOW);
  }
  return ret;
}

#ifdef HAVE_STATX
void
copy_statx_to_stat_time (struct statx_timestamp *stx, struct timespec *st)
{
  st->tv_sec = stx->tv_sec;
  st->tv_nsec = stx->tv_nsec;
}

void
statx_to_stat (struct statx *stx, struct stat *st)
{
  st->st_dev = makedev (stx->stx_dev_major, stx->stx_dev_minor);
  st->st_ino = stx->stx_ino;
  st->st_mode = stx->stx_mode;
  st->st_nlink = stx->stx_nlink;
  st->st_uid = stx->stx_uid;
  st->st_gid = stx->stx_gid;
  st->st_rdev = makedev (stx->stx_rdev_major, stx->stx_rdev_minor);
  st->st_size = stx->stx_size;
  st->st_blksize = stx->stx_blksize;
  st->st_blocks = stx->stx_blocks;
  copy_statx_to_stat_time (&stx->stx_atime, &st->st_atim);
  copy_statx_to_stat_time (&stx->stx_ctime, &st->st_ctim);
  copy_statx_to_stat_time (&stx->stx_mtime, &st->st_mtim);
}
#endif

int
strconcat3 (char *dest, size_t size, const char *s1, const char *s2, const char *s3)
{
  size_t t;
  char *current = dest;

  size--;

  if (s1)
    {
      t = strlen (s1);
      if (t > size)
        t = size;

      memcpy (current, s1, t);
      current += t;

      size -= t;
    }
  if (s2)
    {
      t = strlen (s2);
      if (t > size)
        t = size;

      memcpy (current, s2, t);
      current += t;

      size -= t;
    }
  if (s3)
    {
      t = strlen (s3);
      if (t > size)
        t = size;

      memcpy (current, s3, t);
      current += t;
    }
  *current = '\0';

  return current - dest;
}

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

void
cleanup_closep (void *p)
{
  int *pp = p;
  if (*pp >= 0)
    TEMP_FAILURE_RETRY (close (*pp));
}

void
cleanup_dirp (DIR **p)
{
  DIR *dir = *p;
  if (dir)
    closedir (dir);
}

int
open_fd_or_get_path (struct ovl_layer *l, const char *path, char *out, int *fd, int flags)
{
  out[0] = '\0';

  *fd = l->ds->openat (l, path, O_NONBLOCK|O_NOFOLLOW|flags, 0);
  if (*fd < 0 && (errno == ELOOP || errno == EISDIR || errno == ENXIO))
    {
      strconcat3 (out, PATH_MAX, l->path, "/", path);
      return 0;
    }

  return *fd;
}

int
override_mode (struct ovl_layer *l, int fd, const char *abs_path, const char *path, struct stat *st)
{
  int ret;
  uid_t uid;
  gid_t gid;
  mode_t mode;
  char buf[64];
  cleanup_close int cleanup_fd = -1;
  const char *xattr_name;

  switch (st->st_mode & S_IFMT)
    {
    case S_IFDIR:
    case S_IFREG:
      break;

    default:
      return 0;
    }

  switch (l->stat_override_mode)
    {
    case STAT_OVERRIDE_NONE:
      return 0;

    case STAT_OVERRIDE_USER:
      xattr_name = XATTR_OVERRIDE_STAT;
      break;

    case STAT_OVERRIDE_PRIVILEGED:
      xattr_name = XATTR_PRIVILEGED_OVERRIDE_STAT;
      break;

    case STAT_OVERRIDE_CONTAINERS:
      xattr_name = XATTR_OVERRIDE_CONTAINERS_STAT;
      break;

    default:
      errno = EINVAL;
      return -1;
    }

  if (fd >= 0)
    {
      ret = ufgetxattr (fd, xattr_name, buf, sizeof (buf) - 1);
      if (ret < 0)
        return ret;
    }
  else if (abs_path)
    {
      ret = ulgetxattr (abs_path, xattr_name, buf, sizeof (buf) - 1);
      if (ret < 0)
        return ret;
    }
  else
    {
      char full_path[PATH_MAX];

      full_path[0] = '\0';
      ret = open_fd_or_get_path (l, path, full_path, &cleanup_fd, O_RDONLY);
      if (ret < 0)
        return ret;
      fd = cleanup_fd;

      if (fd >= 0)
        ret = ufgetxattr (fd, xattr_name, buf, sizeof (buf) - 1);
      else
        {
          ret = ulgetxattr (full_path, xattr_name, buf, sizeof (buf) - 1);
          if (ret < 0 && errno == ENODATA)
            return 0;
        }

      if (ret < 0)
        return ret;
    }

  buf[ret] = '\0';

  ret = sscanf (buf, "%d:%d:%o", &uid, &gid, &mode);
  if (ret != 3)
    {
      errno = EINVAL;
      return -1;
    }

  st->st_uid = uid;
  st->st_gid = gid;
  st->st_mode = (st->st_mode & S_IFMT) | mode;

  return 0;
}

enum units char_to_units(const char c) {
    switch (c) {
        case 'B':
            return BYTES;
        case 'K':
            return KILOBYTES;
        case 'M':
            return MEGABYTES;
        case 'G':
            return GIGABYTES;
        case 'T':
            return TERABYTES;
        default:
            return BYTES;
    }
}

// 当前文件夹资源剩余大小
static atomic_long global_quota;
char global_path[PATH_MAX];

unsigned long min(unsigned long l1, unsigned long l2) {
    return l1 < l2 ? l1 : l2;
}

int quota_set(const char* basepath, const char *path, unsigned long size, enum units unit) {
    strcpy(global_path, path);
    char real_quota_path[PATH_MAX] = "";
    strcpy(real_quota_path, basepath);
    strcat(real_quota_path, "/");
    strcat(real_quota_path, path);
    ssize_t space_of_path = space(real_quota_path);
    if (space_of_path == -1) {
        return -1;
    }
    printf("space of %s(%s): %ld\n", path, real_quota_path, space_of_path);
    global_quota = ATOMIC_VAR_INIT((size * unit) - space_of_path);
    printf("space initialzed!the remain size is [%ld]\n", global_quota);
    return 0;
}

long double quota_get(const char *path, enum units unit) {
    if (limited(path))
        return (long double) global_quota / unit;
    return -1;
}

/**
 * Determines if a write can succeed under the quota restrictions.
 */
long quota_exceeded(const char *path) {
    if (limited(path))
        return global_quota;
    return 1;
}

atomic_long *get_global_quota() {
  return &global_quota;
}   

// 增加文件夹容量 （减少 quota，也就是剩余可容纳的容量）
long incr_size(long s) {
    long original_quota, result_quota;
    do {
        original_quota = global_quota;
        result_quota = 0;
        if (original_quota > s)
            result_quota = original_quota - s;
    } while (!atomic_compare_exchange_weak(&global_quota, &original_quota, result_quota));

    // printf("the oringinal quota is %ld, incr size is %ld,the result quota is %ld\n", original_quota, s,
    //         global_quota);
    return global_quota;
}


void quota_unset(const char *path) {
    if (limited(path)) {
        global_quota = LONG_MAX;
        strcpy(global_path, "");
    }
}

int limited(const char *path) {
    // printf("global path is %s,target path is %s\n", global_path, path);
    if (strncmp(path, global_path, strlen(global_path)) == 0)
        return 1;
    return 0;
}

ssize_t directory_size(const char *path) {
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) {
        if (errno == EACCES)
            return 0;

        return -1;
    } else if (sfs.f_type == 0x9fa0)
        return 0;

    if (chdir(path) != 0) {
        if (errno == EACCES)
            return 0;

//        error("From directory_size.chdir");
        return -1;
    }

    DIR *dir = opendir(".");

    if (dir == NULL) {
        if (errno == EACCES)
            return 0;

        return -1;
    }

    struct dirent *ent = NULL;
    ssize_t size = 0;

    while ((ent = readdir(dir)) != NULL) {
        if ((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0))
            continue;

        ssize_t s = entry_size(ent->d_name);
        if (s == -1) {
            return -1;
        }
        size += s;
    }

    if (chdir("..") != 0)
        return -1;

    if (closedir(dir) != 0)
        return -1;

    return size;
}

ssize_t entry_size(const char *path) {
    struct stat buf;
    if (lstat(path, &buf) != 0)
        return -1;

    if (S_ISDIR(buf.st_mode)) {
        ssize_t dir_size = directory_size(path);
        if (dir_size == -1) {
            return -1;
        }
        return buf.st_size + dir_size;
    } else
        return buf.st_size;
}

ssize_t space(const char *path) {
    char fpath[PATH_MAX];
    if (realpath(path, fpath) == NULL)
        return 0;
    return entry_size(fpath);
}
static char GLOBAL_DB_PATH[PATH_MAX] = "";
static char MOUNT_BASE_DIR[PATH_MAX];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static leveldb_t* DB = NULL;

static leveldb_readoptions_t* roptions = NULL;
static leveldb_writeoptions_t* woptions = NULL;

bool
file_exists(char* filename)
{
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

int
mkdir_all(char* folder_path)
{
    if (!access(folder_path, F_OK)) {
        return 1;
    }

    char path[PATH_MAX];
    char* path_buf;
    char temp_path[PATH_MAX];
    char* temp;
    size_t temp_len;

    memset(path, 0, sizeof(path));
    memset(temp_path, 0, sizeof(temp_path));
    strcat(path, folder_path);
    path_buf = path;

    while ((temp = strsep(&path_buf, "/")) != NULL) {
        temp_len = strlen(temp);
        if (0 == temp_len) {
            continue;
        }
        strcat(temp_path, "/");
        strcat(temp_path, temp);
        if (-1 == access(temp_path, F_OK)) {
            if (-1 == mkdir(temp_path, 0744)) {
                return 2;
            }
        }
    }
    return 1;
}

void
local_xattr_db_init(const char* db_parent_dir)
{
    strcpy(GLOBAL_DB_PATH, db_parent_dir);
}

int xattr_initialized(){
  return GLOBAL_DB_PATH[0] == '\0' ? 0 : 1;
}

void
local_xattr_db_release()
{
    pthread_mutex_lock(&mutex);
    if (DB != NULL) {
        leveldb_close(DB);
        leveldb_readoptions_destroy(roptions);
        leveldb_writeoptions_destroy(woptions);
    }
    pthread_mutex_unlock(&mutex);
}

leveldb_t*
create_db()
{
    if (!file_exists(GLOBAL_DB_PATH)) {
        mkdir_all(GLOBAL_DB_PATH);
    }
    printf("GLOBAL_DB_PATH is %s\n", GLOBAL_DB_PATH);
    leveldb_t* db;
    leveldb_options_t* options;
    char* err = NULL;

    options = leveldb_options_create();
    leveldb_options_set_create_if_missing(options, 1);
    db = leveldb_open(options, GLOBAL_DB_PATH, &err);

    if (err != NULL) {
        fprintf(stderr, "Get DB fail: %s\n", err);
        leveldb_free(err);
        return NULL;
    }

    roptions = leveldb_readoptions_create();
    woptions = leveldb_writeoptions_create();
    return db;
}

leveldb_t*
get_db()
{
    if (DB != NULL) {
        return DB;
    }
    pthread_mutex_lock(&mutex);
    if (DB != NULL) {
        return DB;
    }
    DB = create_db();
    pthread_mutex_unlock(&mutex);
    return DB;
}


// 通过 inode number 获取 key
char*
get_db_key(unsigned long ino, const char* name, size_t* result_len)
{

    char prefix[11];

    sprintf(prefix,"%ld",ino);

    size_t prefix_len = strlen(prefix);
    *result_len = (prefix_len + strlen(name) + 1);
    char* buf = (char*)malloc(sizeof(char) * ((*result_len) + 2));

    strcpy(buf, prefix);
    strcpy(buf + prefix_len + 1, name);

    return buf;
}

const char*
unwrap_db_key(size_t path_len,
              const char* key,
              size_t key_len,
              size_t* result_len)
{
    *result_len = key_len - path_len - 1;
    return key + path_len + 1;
}

int ufsetxattr(int fd, const char *name,
                  const void *value, size_t size, int flags){
    if(!xattr_initialized()){
      return fsetxattr(fd, name, value, size, flags);
    }
    struct stat file_stat;  
    int ret = fstat (fd, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_set_xattr(file_stat.st_ino,name,value,size,flags);
}


int ulsetxattr(const char* path,
              const char* name,
              const char* value,
              size_t size,
              int flags)
{
  if(!xattr_initialized()){
      return lsetxattr(path, name, value, size, flags);
  }
  struct stat file_stat;  
  int ret = lstat (path, &file_stat);
  if (ret < 0) {
    return -1;
  }
  return local_set_xattr(file_stat.st_ino,name,value,size,flags);
}

int usetxattr(const char* path,
              const char* name,
              const char* value,
              size_t size,
              int flags) {
  if(!xattr_initialized()){
      return setxattr(path, name, value, size, flags);
  }
  struct stat file_stat;
  char fpath[PATH_MAX];
  if(realpath(path,fpath) == NULL) {
      return -1;
  }
  int ret = lstat (fpath, &file_stat);
  if (ret < 0) {
      return -1;
  }
  return local_set_xattr(file_stat.st_ino,name,value,size,flags);
}

int local_set_xattr(ino_t ino, const char *name, const void *value, size_t size, int flags) {
    leveldb_t* db = get_db();
    char* original_value;
    char* err = NULL;

    size_t name_len;
    char* wrapped_name = get_db_key(ino, name, &name_len);

    if (db != NULL) {

        size_t vallen = 0;
        original_value =
                leveldb_get(db, roptions, wrapped_name, name_len, &vallen, &err);
        if (err != NULL) {
            fprintf(stderr, "Get attr fail: %s\n", err);
            errno = ENOTSUP;

            leveldb_free(err);
            free(wrapped_name);

            return -1;
        }
    }

    if (flags == 0 || (original_value == NULL && flags == XATTR_CREATE) ||
        (original_value != NULL && flags == XATTR_REPLACE)) {
        leveldb_put(db, woptions, wrapped_name, name_len, value, size, &err);

        leveldb_free(original_value);
        free(wrapped_name);

        if (err != NULL) {
            fprintf(stderr, "Set attr fail: %s\n", err);
            errno = ENOTSUP;
            leveldb_free(err);
            return -1;
        }
        return 0;
    }

    if (original_value == NULL && flags == XATTR_REPLACE)
        errno = ENODATA;
    else if (original_value != NULL && flags == XATTR_CREATE)
        errno = EEXIST;

    leveldb_free(original_value);
    free(wrapped_name);

    return -1;

}

ssize_t local_get_xattr(ino_t ino, const char* name, char* value, size_t size){

     leveldb_t* db = get_db();

    if (db == NULL) {
        errno = ENODATA;
        return -1;
    }
    char* err = NULL;
    size_t name_len;
    char* wrapped_name = get_db_key(ino, name, &name_len);

    size_t vallen;
    char* db_store_value =
            leveldb_get(db, roptions, wrapped_name, name_len, &vallen, &err);

    free(wrapped_name);

    if (err != NULL) {
        fprintf(stderr, "Get attr fail: %s\n", err);
        leveldb_free(err);

        errno = ENOTSUP;
        return -1;
    }

    if (db_store_value == NULL) {
        errno = ENODATA;
        return -1;
    }

    if (size != 0) {
        if (vallen <= size) {
            strcpy(value, db_store_value);
            printf("value = %s,size = %ld\n", value, size);
        } else {
            errno = ERANGE;
            leveldb_free(db_store_value);
            return -1;
        }
    }

    leveldb_free(db_store_value);
    return vallen;
}

ssize_t ufgetxattr(int fd, const char *name,
                  void *value, size_t size) {
  if(!xattr_initialized()){
      return fgetxattr(fd, name, value, size);
  }
    struct stat file_stat;  
    int ret = fstat (fd, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_get_xattr(file_stat.st_ino,name,value,size);
}
ssize_t
ulgetxattr(const char* path, const char* name, char* value, size_t size)
{
  if(!xattr_initialized()){
      return lgetxattr(path, name, value, size);
  }
    struct stat file_stat;  
    int ret = lstat (path, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_get_xattr(file_stat.st_ino,name,value,size);
}

ssize_t
ugetxattr(const char* path, const char* name, char* value, size_t size)
{
  if(!xattr_initialized()){
      return getxattr(path, name, value, size);
  }
    struct stat file_stat;
    char fpath[PATH_MAX];
    if(realpath(path,fpath) == NULL) {
        return -1;
    }
    int ret = lstat (fpath, &file_stat);
    if (ret < 0) {
        return -1;
    }
    return local_get_xattr(file_stat.st_ino,name,value,size);
}

size_t local_list_xattr(ino_t ino,char* list,size_t size) {
    leveldb_t* db = get_db();
    if (db == NULL) {
        return 0;
    }
    char prefix[11];
    sprintf("%s",prefix,ino);
    size_t path_len = strlen(prefix);

    leveldb_iterator_t* iter = leveldb_create_iterator(db, roptions);
    if (size == 0) {
        size_t len = 0;
        for (leveldb_iter_seek(iter, prefix, path_len); leveldb_iter_valid(iter);
             leveldb_iter_next(iter)) {
            size_t vallen;
            const char* key = leveldb_iter_key(iter, &vallen);
            if (strcmp(key, prefix) != 0)
                break;
            size_t key_len;
            unwrap_db_key(path_len, key, vallen, &key_len);
            len += key_len + 1;
        }
        leveldb_iter_destroy(iter);
        printf("len = %d\n", (int)len);
        return (int)len;
    }
    size_t len = 0;
    for (leveldb_iter_seek(iter, prefix, path_len); leveldb_iter_valid(iter);
         leveldb_iter_next(iter)) {
        if (size < len) {
            errno = ERANGE;
            leveldb_iter_destroy(iter);
            return -1;
        }
        size_t vallen;
        const char* key = leveldb_iter_key(iter, &vallen);
        if (strcmp(key, prefix) != 0)
            break;
        size_t key_len;
        const char* result_key = unwrap_db_key(path_len, key, vallen, &key_len);
        memcpy(list + len, result_key, key_len);
        len += key_len + 1;
        *(list + len - 1) = '\0';
    }
    leveldb_iter_destroy(iter);

    return len;
}

ssize_t uflistxattr(int fd, char *list, size_t size) {
  if(!xattr_initialized()){
      return flistxattr(fd, list, size);
  }
    struct stat file_stat;  
    int ret = fstat (fd, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_list_xattr(file_stat.st_ino, list, size);
}

ssize_t
ullistxattr(const char* path, char* list, size_t size)
{
  if(!xattr_initialized()){
      return llistxattr(path, list, size);
  }
    struct stat file_stat;  
    int ret = lstat (path, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_list_xattr(file_stat.st_ino, list, size);
}

ssize_t ulistxattr(const char* path, char* list, size_t size){
  if(!xattr_initialized()){
      return listxattr(path, list, size);
  }
    struct stat file_stat;
    char fpath[PATH_MAX];
    if(realpath(path,fpath) == NULL) {
        return -1;
    }
    int ret = lstat (fpath, &file_stat);
    if (ret < 0) {
        return -1;
    }
    return local_list_xattr(file_stat.st_ino, list, size);
}

int local_remove_xattr(ino_t ino, const char* name) {
    leveldb_t* db = get_db();
    if (db == NULL) {
        errno = ENODATA;
        return -1;
    }

    char* err = NULL;

    size_t name_len;
    char* wrapped_name = get_db_key(ino, name, &name_len);
    size_t vallen = 0;
    char* db_store_value =
            leveldb_get(db, roptions, wrapped_name, name_len, &vallen, &err);
    if (err != NULL) {
        fprintf(stderr, "Get attr fail: %s\n", err);
        errno = ENOTSUP;
        free(wrapped_name);
        return -1;
    }
    leveldb_free(err);
    err = NULL;
    if (db_store_value == NULL) {
        free(wrapped_name);
        errno = ENODATA;
        return -1;
    }

    leveldb_delete(db, woptions, wrapped_name, name_len, &err);
    if (err != NULL) {
        fprintf(stderr, "Delete attr fail: %s\n", err);
        errno = ENOTSUP;
        leveldb_free(err);
        err = NULL;
        free(wrapped_name);
        return -1;
    }
    free(wrapped_name);
    return 0;
}

int ufremovexattr(int fd, const char *name) {
  if(!xattr_initialized()){
      return fremovexattr(fd, name);
  }
    struct stat file_stat;  
    int ret = fstat (fd, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_remove_xattr(file_stat.st_ino, name);
}

int
ulremovexattr(const char* path, const char* name)
{
  if(!xattr_initialized()){
      return lremovexattr(path, name);
  }
    struct stat file_stat;  
    int ret = lstat (path, &file_stat);  
    if (ret < 0) {  
      return -1;
    }
    return local_remove_xattr(file_stat.st_ino, name);
}

int
uremovexattr(const char* path, const char* name)
{
  if(!xattr_initialized()){
      return removexattr(path, name);
  }
    struct stat file_stat;
    char fpath[PATH_MAX];
    if(realpath(path,fpath) == NULL) {
        return -1;
    }
    int ret = lstat (fpath, &file_stat);
    if (ret < 0) {
        return -1;
    }
    return local_remove_xattr(file_stat.st_ino, name);
}

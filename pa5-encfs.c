/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <limits.h> // PATH_MAX
#include "aes-crypt.h"

#define FUSE_DATA ((encfs_state*) fuse_get_context()->private_data)
#define TMP_EXT ".tmp"
#define ENCRYPT 1
#define DECRYPT 0
#define ATTR_STORAGE "user.enc"

typedef struct {
	char *path_from_root;
	char *key;
} encfs_state;

static void get_new_path(char new_path[PATH_MAX], const char *path) {
	encfs_state *state = FUSE_DATA;
	strcpy(new_path, state->path_from_root);
	strncat(new_path, path, PATH_MAX);
}

static int encfs_getattr(const char *path, struct stat *stbuf)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = lstat(new_path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = access(new_path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = readlink(new_path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
						 off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	(void) offset;
	(void) fi;

	dp = opendir(new_path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(new_path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(new_path, mode);
	else
		res = mknod(new_path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_mkdir(const char *path, mode_t mode)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = mkdir(new_path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = unlink(new_path);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = rmdir(new_path);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = chmod(new_path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = lchown(new_path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = truncate(new_path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(new_path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = open(new_path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
					  struct fuse_file_info *fi)
{
	int fd;
	int res;
	char new_path[PATH_MAX];
	FILE *fp, *tmp;

	get_new_path(new_path, path);

	(void) fi;

	if (getxattr(new_path, ATTR_STORAGE, NULL, 0) >= 0) {
		char* tmppath;
		tmppath = malloc(sizeof(char)*(strlen(new_path) + strlen(TMP_EXT) + 1));
		tmppath[0] = '\0';
		strcat(tmppath, new_path);
		strcat(tmppath, TMP_EXT);

		tmp = fopen(tmppath, "wb+");
		fp = fopen(new_path, "rb");

		do_crypt(fp, tmp, DECRYPT, FUSE_DATA->key);

		fseek(tmp, 0, SEEK_END);
		size_t len = ftell(tmp);
		fseek(tmp, 0, SEEK_SET);

		res = fread(buf, 1, len, tmp);
		if (res == -1)
			return -errno;

		fclose(fp);
		fclose(tmp);
		remove(tmppath);
	}
	else {
		fd = open(new_path, O_RDONLY);
		if (fd == -1)
			return -errno;

		res = pread(fd, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd);
	}

	return res;
}

static int encfs_write(const char *path, const char *buf, size_t size,
					   off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;
	char new_path[PATH_MAX];
	FILE *fp, *tmp;

	get_new_path(new_path, path);

	(void) fi;

	if (getxattr(new_path, ATTR_STORAGE, NULL, 0) >= 0) {
		char* tmppath;
		tmppath = malloc(sizeof(char)*(strlen(new_path) + strlen(TMP_EXT) + 1));
		tmppath[0] = '\0';
		strcat(tmppath, new_path);
		strcat(tmppath, TMP_EXT);

		fp = fopen(new_path, "rb+");
		tmp = fopen(tmppath, "wb+");

		fseek(fp, 0, SEEK_SET);

		do_crypt(fp, tmp, DECRYPT, FUSE_DATA->key);

		fseek(fp, 0, SEEK_SET);

		res = fwrite(buf, 1, size, tmp);
		if (res == -1)
			return -errno;

		fseek(tmp, 0, SEEK_SET);

		do_crypt(tmp, fp, ENCRYPT, FUSE_DATA->key);

		fclose(fp);
		fclose(tmp);
		remove(tmppath);
	} else {
		fd = open(new_path, O_WRONLY);
		if (fd == -1)
			return -errno;

		res = pwrite(fd, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd);
	}

	return res;
}

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	res = statvfs(new_path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

	(void) fi;

	FILE *fp;
	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	int res;
	res = creat(new_path, mode);
	if(res == -1)
		return -errno;

	fp = fdopen(res, "w");
	close(res);

	do_crypt(fp, fp, ENCRYPT, FUSE_DATA->key);

	fclose(fp);

	if (setxattr(new_path, ATTR_STORAGE, "true", 4, 0) == -1) {
		return -errno;
	}

	return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
					   struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
						  size_t size, int flags)
{
	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	int res = lsetxattr(new_path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value,
						  size_t size)
{
	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	int res = lgetxattr(new_path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	char new_path[PATH_MAX];
	get_new_path(new_path, path);

	int res = llistxattr(new_path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	char new_path[PATH_MAX];

	get_new_path(new_path, path);

	int res = lremovexattr(new_path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations encfs_oper = {
		.getattr	= encfs_getattr,
		.access		= encfs_access,
		.readlink	= encfs_readlink,
		.readdir	= encfs_readdir,
		.mknod		= encfs_mknod,
		.mkdir		= encfs_mkdir,
		.symlink	= encfs_symlink,
		.unlink		= encfs_unlink,
		.rmdir		= encfs_rmdir,
		.rename		= encfs_rename,
		.link		= encfs_link,
		.chmod		= encfs_chmod,
		.chown		= encfs_chown,
		.truncate	= encfs_truncate,
		.utimens	= encfs_utimens,
		.open		= encfs_open,
		.read		= encfs_read,
		.write		= encfs_write,
		.statfs		= encfs_statfs,
		.create         = encfs_create,
		.release	= encfs_release,
		.fsync		= encfs_fsync,
#ifdef HAVE_SETXATTR
		.setxattr	= encfs_setxattr,
		.getxattr	= encfs_getxattr,
		.listxattr	= encfs_listxattr,
		.removexattr	= encfs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);

	if (argc < 4) {
		fprintf(stderr, "Usage: <Key> <Mirror Directory> <Mount Point> \n");
		exit(EXIT_FAILURE);
	}

	encfs_state *encfs_data;
	encfs_data = malloc(sizeof(encfs_state));

	encfs_data->key = argv[1];
	encfs_data->path_from_root = realpath(argv[2], NULL);

	return fuse_main(argc - 2, argv + 2, &encfs_oper, encfs_data);
}

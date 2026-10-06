/*
 * victim.c - target program used to demonstrate the rootkit
 * COMP60024 OSIB - Part C
 * Student: Faraj Farook   ID: CB012653
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>

extern char **environ;

int main(void)
{
    char buf[256];
    int fd, n;
    pid_t pid;

    printf("[victim] starting: uid=%d euid=%d pid=%d\n", getuid(), geteuid(), getpid());

    printf("\n[victim] --- file access test ---\n");
    fd = open("/tmp/secret.txt", O_RDONLY);
    if (fd < 0) {
        perror("[victim] open(\"/tmp/secret.txt\") FAILED");
    } else {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("[victim] read %d bytes: %s", n, buf);
        }
        close(fd);
    }

    printf("\n[victim] --- directory listing test ---\n");
    system("ls -l /tmp/secret.txt 2>&1 || echo '[victim] secret.txt not visible to ls'");

    printf("\n[victim] --- process execution test ---\n");
    pid = fork();
    if (pid == 0) {
        char *argv[] = { "/bin/uname", "-a", NULL };
        execve("/bin/uname", argv, environ);
        perror("[victim] execve failed");
        _exit(127);
    }
    waitpid(pid, NULL, 0);
    printf("[victim] child finished\n");
    return 0;
}

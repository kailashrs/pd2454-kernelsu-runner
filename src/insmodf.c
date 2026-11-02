/* SPDX-License-Identifier: GPL-2.0-only
 * One-shot exact-ABI module insertion. No force flags or alternate module. */
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv)
{
    if (argc!=4 || strcmp(argv[2],"0")) {
        fputs("usage: insmodf <bound-module.ko> 0 <module-parameters>\n",stderr);
        return 2;
    }
    int fd=open(argv[1],O_RDONLY|O_CLOEXEC);
    if (fd<0) {perror("insmodf: open");return 1;}
    long rc=syscall(SYS_finit_module,fd,argv[3],0);
    int saved_errno=errno;
    close(fd);
    if (rc==0) {printf("MODULE_LOAD_PASS %s\n",argv[1]);return 0;}
    fprintf(stderr,"MODULE_LOAD_FAIL errno=%d (%s)\n",saved_errno,strerror(saved_errno));
    return 1;
}

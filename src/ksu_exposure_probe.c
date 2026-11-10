// ksu_exposure_probe: unprivileged KernelSU visibility matrix.
//
// Prints one TAG=VALUE line per detection channel so outputs can be diffed
// between a stock boot and a KernelSU boot. Any line that differs (other
// than the self-explanatory probe metadata) is a detection surface.
//
// Channels:
//   modules       /proc/modules lines matching kernelsu/ksu
//   sysfs         /sys/module/kernelsu presence
//   kallsyms      /proc/kallsyms symbol names matching ksu (addresses are
//                 zeroed by kptr_restrict; names are the leak)
//   dmesg         klogctl(2)/SYS_syslog ring read + grep KernelSU/ksu
//   kmsg          /dev/kmsg open attempt
//   fd_install    reboot-magic handshake: new fd appearing after the call
//                 (stock: none; ungated KSU: [ksu_driver] fd appears)
//   get_info      ioctl on any fd obtained above (ungated KSU: version)
//   devices       /proc/devices + /proc/misc ksu entries
//   su_paths      stat/access errno matrix on classic su locations
//   capbset       prctl(23/24) sweep (control: identical on stock kernels)
//   procs         /proc/*/comm entries readable and matching ksud

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KSU_INSTALL_MAGIC1 0xDEADBEEFu
#define KSU_INSTALL_MAGIC2 0xCAFEBABEu

struct ksu_get_info_cmd {
    unsigned int version;
    unsigned int flags;
    unsigned int features;
    unsigned int uapi_version;
};

#define KSU_IOCTL_GET_INFO_NR _IOR('K', 2, struct ksu_get_info_cmd)

static int contains_ksu(const char *s)
{
    return strcasestr(s, "kernelsu") != NULL || strcasestr(s, "ksu") != NULL;
}

static void check_file_lines(const char *tag, const char *path)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int hits = 0;
    char first[256] = "";

    if (!f) {
        printf("%s=open_errno_%d\n", tag, errno);
        return;
    }
    while (fgets(line, sizeof(line), f)) {
        if (contains_ksu(line)) {
            hits++;
            if (!first[0]) {
                char *nl = strchr(line, '\n');
                if (nl)
                    *nl = 0;
                snprintf(first, sizeof(first), "%.120s", line);
            }
        }
    }
    fclose(f);
    if (hits)
        printf("%s=HITS_%d first=[%s]\n", tag, hits, first);
    else
        printf("%s=CLEAN\n", tag);
}

static int fd_count_snapshot(int *fds, int max)
{
    DIR *d = opendir("/proc/self/fd");
    struct dirent *de;
    char selfbuf[32];
    int n = 0;

    if (!d)
        return 0;
    snprintf(selfbuf, sizeof(selfbuf), "%d", dirfd(d));
    while ((de = readdir(d)) && n < max) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        if (strcmp(de->d_name, selfbuf) == 0)
            continue;
        fds[n++] = atoi(de->d_name);
    }
    closedir(d);
    return n;
}

static int fd_in_set(int fd, const int *fds, int n)
{
    for (int i = 0; i < n; i++)
        if (fds[i] == fd)
            return 1;
    return 0;
}

int main(void)
{
    static const char *su_paths[] = {
        "/system/bin/su",     "/system/xbin/su",    "/sbin/su",
        "/system/sd/xbin/su", "/vendor/bin/su",     "/su/bin/su",
        "/data/local/su",     "/data/local/bin/su", "/data/local/xbin/su",
    };
    int before[256], after[256];
    int nbefore, nafter, newfd = -1;
    long rc;
    int kmsg_fd;

    printf("probe_uid=%d\n", getuid());

    check_file_lines("modules", "/proc/modules");

    struct stat st;
    if (stat("/sys/module/kernelsu", &st) == 0)
        printf("sysfs=PRESENT\n");
    else
        printf("sysfs=absent_errno_%d\n", errno);

    check_file_lines("kallsyms", "/proc/kallsyms");
    check_file_lines("devices", "/proc/devices");
    check_file_lines("misc", "/proc/misc");

    /* dmesg ring via syslog(2): query the full ring size, then one
     * SYSLOG_ACTION_READ_ALL pass (action 3 is non-consuming, so repeated
     * small reads return the same newest chunk, not pagination). */
    {
        char *buf;
        long size;

        rc = syscall(SYS_syslog, 10, NULL, 0); /* action 10 = size buffer */
        if (rc < 0) {
            printf("dmesg=errno_%ld\n", rc);
        } else {
            size = rc;
            if (size > 8 * 1024 * 1024)
                size = 8 * 1024 * 1024;
            buf = malloc((size_t)size + 1);
            if (!buf) {
                printf("dmesg=oom\n");
            } else {
                int hits = 0;
                char *p;

                rc = syscall(SYS_syslog, 3, buf, size);
                if (rc < 0) {
                    printf("dmesg=read_errno_%ld\n", rc);
                } else {
                    buf[rc < size ? rc : size] = 0;
                    p = buf;
                    while ((p = strcasestr(p, "kernelsu")) != NULL) {
                        hits++;
                        p += 8;
                    }
                    p = buf;
                    while ((p = strcasestr(p, "ksu")) != NULL) {
                        hits++;
                        p += 3;
                    }
                    if (hits)
                        printf("dmesg=HITS_%d\n", hits);
                    else
                        printf("dmesg=CLEAN\n");
                }
                free(buf);
            }
        }
    }

    kmsg_fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if (kmsg_fd < 0)
        printf("kmsg=open_errno_%d\n", errno);
    else
        printf("kmsg=OPEN\n");
    if (kmsg_fd >= 0)
        close(kmsg_fd);

    /* reboot-magic fd handshake */
    nbefore = fd_count_snapshot(before, 256);
    {
        int out = -1;
        errno = 0;
        rc = syscall(SYS_reboot, (int)KSU_INSTALL_MAGIC1, (int)KSU_INSTALL_MAGIC2, 0, &out);
    }
    nafter = fd_count_snapshot(after, 256);
    for (int i = 0; i < nafter; i++) {
        if (!fd_in_set(after[i], before, nbefore)) {
            newfd = after[i];
            break;
        }
    }
    (void)rc;
    if (newfd >= 0) {
        printf("fd_install=NEW_FD_%d\n", newfd);
        struct ksu_get_info_cmd info;
        memset(&info, 0, sizeof(info));
        if (ioctl(newfd, KSU_IOCTL_GET_INFO_NR, &info) == 0)
            printf("get_info=VERSION_%u_flags_0x%x\n", info.version, info.flags);
        else
            printf("get_info=ioctl_errno_%d\n", errno);
        close(newfd);
    } else {
        printf("fd_install=NONE\n");
        printf("get_info=skipped\n");
    }

    /* su path matrix */
    for (size_t i = 0; i < sizeof(su_paths) / sizeof(su_paths[0]); i++) {
        errno = 0;
        if (stat(su_paths[i], &st) == 0)
            printf("su_path=%s STAT_OK mode=0%o\n", su_paths[i], st.st_mode);
        else
            printf("su_path=%s stat_errno=%d\n", su_paths[i], errno);
        errno = 0;
        if (access(su_paths[i], X_OK) == 0)
            printf("su_exec=%s ACCESS_OK\n", su_paths[i]);
        else
            printf("su_exec=%s access_errno=%d\n", su_paths[i], errno);
    }

    /* capability bounding set sweep (stock control channel) */
    {
        int ones = 0, zeros = 0, errs = 0;
        for (int cap = 0; cap <= 41; cap++) {
            errno = 0;
            long r = prctl(PR_CAPBSET_READ, (unsigned long)cap, 0, 0, 0);
            if (r == 1)
                ones++;
            else if (r == 0)
                zeros++;
            else
                errs++;
        }
        printf("capbset=ones_%d_zeros_%d_errs_%d\n", ones, zeros, errs);
    }

    /* readable process names matching ksud */
    {
        DIR *d = opendir("/proc");
        struct dirent *de;
        int readable = 0, hits = 0;

        if (d) {
            while ((de = readdir(d))) {
                char p[128], comm[64];
                int cfd;
                if (de->d_name[0] < '0' || de->d_name[0] > '9')
                    continue;
                snprintf(p, sizeof(p), "/proc/%s/comm", de->d_name);
                cfd = open(p, O_RDONLY);
                if (cfd < 0)
                    continue;
                readable++;
                ssize_t n = read(cfd, comm, sizeof(comm) - 1);
                close(cfd);
                if (n > 0) {
                    comm[n] = 0;
                    if (strstr(comm, "ksud"))
                        hits++;
                }
            }
            closedir(d);
        }
        printf("procs=readable_%d_ksud_hits_%d\n", readable, hits);
    }

    printf("PROBE_DONE\n");
    return 0;
}

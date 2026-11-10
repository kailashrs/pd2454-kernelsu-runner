// ksuquery: root-side KernelSU liveness probe for the hidden-module profile.
//
// The module may no longer be listed in /proc/modules (CONFIG_KSU_HIDE_MODULE),
// so "is it alive?" is answered through the gated supercall handshake itself:
// the reboot-magic fd install (allowed for root/manager only) followed by
// KSU_IOCTL_GET_INFO. Running as root must print KSU_VERSION=...; running as
// an unprivileged uid must print KSU_ABSENT (that asymmetry is the gate
// working as intended).
//
// Exit codes: 0 = module alive (version obtained), 1 = absent/denied.

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
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

int main(void)
{
    struct ksu_get_info_cmd info;
    long rc;
    int fd = -1;

    memset(&info, 0, sizeof(info));

    /* The kprobe fires at syscall entry; the fd arrives via task_work on
     * return to userspace. The reboot syscall itself fails (bad magic from
     * the kernel's point of view); that is expected and harmless. */
    rc = syscall(SYS_reboot, (int)KSU_INSTALL_MAGIC1, (int)KSU_INSTALL_MAGIC2, 0, &fd);
    (void)rc;

    if (fd < 0) {
        printf("KSU_ABSENT no_fd uid=%d\n", getuid());
        return 1;
    }

    if (ioctl(fd, KSU_IOCTL_GET_INFO_NR, &info) < 0) {
        printf("KSU_ABSENT ioctl_errno=%d uid=%d\n", errno, getuid());
        close(fd);
        return 1;
    }

    printf("KSU_VERSION=%u flags=0x%x features=%u uapi=%u uid=%d\n", info.version,
           info.flags, info.features, info.uapi_version, getuid());
    close(fd);
    return 0;
}

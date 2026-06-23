#include "auth_process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

/* Write PID to PID_FILE_PATH; best-effort, non-fatal. */
void write_pid_file(void) {
    FILE *f = fopen(PID_FILE_PATH, "w");
    if (!f) { perror("Warning: Cannot write PID file " PID_FILE_PATH); return; }
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
}
void remove_pid_file(void) { unlink(PID_FILE_PATH); }

/*
 * Drop from root to an unprivileged user[:group] AFTER all listening sockets
 * are bound (port 53 needs root to bind; serving queries does not).  Running a
 * network-facing parser as root for the process lifetime is the avoidable risk
 * here.  No-op when not root; fatal on any failure (silently staying root would
 * defeat the purpose).  `spec` is "user" or "user:group".
 */
void drop_privileges(const char *spec) {
    if (geteuid() != 0) return;                 /* not root — nothing to drop */
    if (!spec || !*spec) {
        fprintf(stderr, "Warning: running as root with no -U user; "
                        "NOT dropping privileges (set -U or a systemd User=)\n");
        return;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *colon = strchr(buf, ':');
    const char *gname = NULL;
    if (colon) { *colon = '\0'; gname = colon + 1; }

    struct passwd *pw = getpwnam(buf);
    if (!pw) { fprintf(stderr, "Error: -U unknown user '%s'\n", buf); exit(EXIT_FAILURE); }
    uid_t uid = pw->pw_uid;
    gid_t gid = pw->pw_gid;
    if (gname && *gname) {
        struct group *gr = getgrnam(gname);
        if (!gr) { fprintf(stderr, "Error: -U unknown group '%s'\n", gname); exit(EXIT_FAILURE); }
        gid = gr->gr_gid;
    }
    if (uid == 0) { fprintf(stderr, "Error: -U user '%s' is root\n", buf); exit(EXIT_FAILURE); }

    if (setgroups(1, &gid) != 0) { perror("Error: setgroups"); exit(EXIT_FAILURE); }
    if (setgid(gid)        != 0) { perror("Error: setgid");    exit(EXIT_FAILURE); }
    if (setuid(uid)        != 0) { perror("Error: setuid");    exit(EXIT_FAILURE); }
    /* Verify root cannot be regained (catches a botched setuid). */
    if (setuid(0) == 0) {
        fprintf(stderr, "Error: privilege drop failed — still able to regain root\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Dropped privileges to %s (uid=%d gid=%d)\n",
            buf, (int)uid, (int)gid);
}

#ifndef AUTH_PROCESS_H
#define AUTH_PROCESS_H

/* Process lifecycle helpers: PID file (write/remove) and the post-bind
 * root -> unprivileged-user privilege drop. */

void write_pid_file(void);
void remove_pid_file(void);
void drop_privileges(const char *spec);

#endif /* AUTH_PROCESS_H */

#include <linux/types.h>

struct k22info {
    char comm[64];                  /* name of the executable */
    pid_t pid;                      /* process ID */
    pid_t parent_pid;               /* parent process ID */
    pid_t first_child_pid;          /* PID of youngest child */
    pid_t next_sibling_pid;         /* PID of oldest sibling */
    unsigned long nvcsw;            /* number of voluntary context switches */
    unsigned long nivcsw;           /* number of involuntary context switches */
    unsigned long start_time;       /* monotonic start time in nanoseconds */
};

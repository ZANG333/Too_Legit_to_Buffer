#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/k22info.h>  // το δικό σου header με struct k22info

#define SYS_K22TREE 477      // αντικατάστησε με τον αριθμό του δικού σου syscall

// helper για να βρούμε τον γονέα στο stack
static int find_parent(int *stack, int top, int parent_pid) {
    for (int i = top; i >= 0; i--) {
        if (stack[i] == parent_pid)
            return i;
    }
    return -1; // δεν βρέθηκε
}

int main() {
    int buf_size = 100;
    struct k22info *buf = malloc(buf_size * sizeof(struct k22info));
    if (!buf) { perror("malloc"); return 1; }

    int ret;
    // επαναλαμβανόμενες κλήσεις μέχρι να χωράει όλα τα στοιχεία
    while (1) {
        ret = syscall(SYS_K22TREE, buf, &buf_size);
        if (ret < 0) {
            perror("k22tree syscall");
            free(buf);
            return 1;
        }
        if (ret <= buf_size)
            break;      // χωράει όλα
        buf_size *= 2;
        buf = realloc(buf, buf_size * sizeof(struct k22info));
        if (!buf) { perror("realloc"); return 1; }
    }

    if (ret == 0) {
        printf("No processes returned.\n");
        free(buf);
        return 0;
    }

    printf("#comm,pid,ppid,fcldpid,nsblpid,nvcsw,nivcsw,stime\n");

    int *stack = malloc(ret * sizeof(int));
    if (!stack) { perror("malloc stack"); free(buf); return 1; }

    int top = 0;
    stack[0] = buf[0].pid;   // root

    // εκτύπωση πρώτης γραμμής
    printf("%s,%d,%d,%d,%d,%ld,%ld,%ld\n",
        buf[0].comm, buf[0].pid, buf[0].parent_pid,
        buf[0].first_child_pid, buf[0].next_sibling_pid,
        buf[0].nvcsw, buf[0].nivcsw, buf[0].start_time);

    for (int i = 1; i < ret; i++) {
        int parent_idx = find_parent(stack, top, buf[i].parent_pid);
        if (parent_idx == -1) parent_idx = 0;

        top = parent_idx + 1;
        stack[top] = buf[i].pid;

        for (int j = 0; j <= top; j++) printf("-");
        printf("%s,%d,%d,%d,%d,%ld,%ld,%ld\n",
            buf[i].comm, buf[i].pid, buf[i].parent_pid,
            buf[i].first_child_pid, buf[i].next_sibling_pid,
            buf[i].nvcsw, buf[i].nivcsw, buf[i].start_time);
    }

    free(buf);
    free(stack);
    return 0;
}

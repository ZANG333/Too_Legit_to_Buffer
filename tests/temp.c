#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#define NUM_CHILDREN 3

void print_cxt_switches(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "voluntary_ctxt_switches", 23) == 0 ||
            strncmp(line, "nonvoluntary_ctxt_switches", 26) == 0) {
            printf("%s", line); // περιλαμβάνει ήδη το newline
        }
    }
    fclose(f);
}

int main() {
    pid_t pids[NUM_CHILDREN];

    for (int i = 0; i < NUM_CHILDREN; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(1);
        } else if (pid == 0) {
            // Child process
            sleep(10); // κρατάμε ζωντανό το child
            exit(0);
        } else {
            pids[i] = pid;
        }
    }

    // Περιμένουμε λίγο για να δημιουργηθούν context switches
    sleep(1);

    printf("Parent PID=%d\n", getpid());
    for (int i = 0; i < NUM_CHILDREN; i++) {
        printf("Child PID=%d\n", pids[i]);
        print_cxt_switches(pids[i]);
        printf("\n");
    }

    // Περιμένουμε να τελειώσουν όλα τα παιδιά
    for (int i = 0; i < NUM_CHILDREN; i++) {
        waitpid(pids[i], NULL, 0);
    }

    return 0;
}

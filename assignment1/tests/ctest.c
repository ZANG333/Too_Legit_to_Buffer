#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>
int main() {
    pid_t parent = getpid();
    printf("Parent PID: %d\n", parent);

    pid_t child1 = fork();
    if (child1 == 0) {
        // Παιδί 1
        printf("Child1 PID: %d, Parent PID: %d\n", getpid(), getppid());
        sleep(5); // κρατάει τη διεργασία ζωντανή για να την δούμε
        exit(0);
    }

    pid_t child2 = fork();
    if (child2 == 0) {
        // Παιδί 2
        printf("Child2 PID: %d, Parent PID: %d\n", getpid(), getppid());
        sleep(5);
        exit(0);
    }

    pid_t child3 = fork();
    if (child3 == 0) {
        // Παιδί 3
        printf("Child3 PID: %d, Parent PID: %d\n", getpid(), getppid());
        sleep(5);
        exit(0);
    }

    // Ο γονέας περιμένει να τερματίσουν τα παιδιά
    for (int i = 0; i < 3; i++) wait(NULL);

    return 0;
}

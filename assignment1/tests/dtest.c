#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t children[6];
    int i;

    printf("Parent PID: %d\n", getpid());

    for (i = 0; i < 6; i++) {
        children[i] = fork();
        if (children[i] == 0) {
            // Κάθε child μένει λίγο ζωντανό για να μπορεί να τσεκαριστεί
            sleep(10);
            return 0;
        }
    }

    // Ο γονέας τυπώνει τα PID των παιδιών
    for (i = 0; i < 6; i++) {
        printf("Child%d PID: %d, Parent PID: %d\n", i+1, children[i], getpid());
    }

    // Ο γονέας περιμένει όλα τα παιδιά να τελειώσουν
    for (i = 0; i < 6; i++) {
        waitpid(children[i], NULL, 0);
    }

    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t children[6];
    int i, j;

    printf("Parent PID: %d\n", getpid());

    for (i = 0; i < 6; i++) {
        children[i] = fork();

        if (children[i] == 0) {
            // Είμαστε στο παιδί
            printf("Child %d PID: %d, Parent PID: %d\n", i+1, getpid(), getppid());

            pid_t grandchildren[2];
            for (j = 0; j < 2; j++) {
                grandchildren[j] = fork();
                if (grandchildren[j] == 0) {
                    // Είμαστε στο εγγόνι
                    printf("    Grandchild %d.%d PID: %d, Parent PID: %d\n",
                           i+1, j+1, getpid(), getppid());
                    sleep(15);
                    return 0;
                }
            }

            // Περιμένει τα δύο παιδιά του (τα εγγόνια του αρχικού γονέα)
            for (j = 0; j < 2; j++) {
                waitpid(grandchildren[j], NULL, 0);
            }

            sleep(10);
            return 0;
        }
    }

    // Ο αρχικός γονέας τυπώνει τα PID των παιδιών
    for (i = 0; i < 6; i++) {
        printf("Parent sees Child %d PID: %d\n", i+1, children[i]);
    }

    // Περιμένει να τελειώσουν όλα τα παιδιά
    for (i = 0; i < 6; i++) {
        waitpid(children[i], NULL, 0);
    }

    return 0;
}

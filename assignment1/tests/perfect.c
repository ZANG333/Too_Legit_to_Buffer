#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/k22info.h>
#include <string.h>
#include <errno.h>

#define K22TREE_SYSCALL 477  // Βάλε τον αριθμό του syscall σου εδ


void test_k22tree(int size, int expect_fail) {
    struct k22info *buf = NULL;
    int ne = size;
    int ret;

    if (size > 0) {
        buf = calloc(size, sizeof(struct k22info));
        if (!buf) {
            perror("calloc");
            return;
        }
    }

    ret = syscall(K22TREE_SYSCALL, buf, &ne);

    if (ret < 0) {
        if (expect_fail) {
            printf("Expected failure, got %d (%s)\n", ret, strerror(-ret));
        } else {
            printf("Unexpected failure: %d (%s)\n", ret, strerror(-ret));
        }
    } else {
        printf("Syscall returned %d processes, ne = %d\n", ret, ne);
        for (int i = 0; i < ne; i++) {
            printf("%2d: pid=%d parent=%d child=%d sibling=%d comm=%s\n",
                   i,
                   buf[i].pid,
                   buf[i].parent_pid,
                   buf[i].first_child_pid,
                   buf[i].next_sibling_pid,
                   buf[i].comm);
        }
    }

    free(buf);
}

int main() {
    printf("=== Test 1: Valid buffer for all processes ===\n");
    test_k22tree(1024, 0);

    printf("\n=== Test 2: Small buffer to trigger truncation ===\n");
    test_k22tree(2, 0);

    printf("\n=== Test 3: Invalid ne pointer ===\n");
    syscall(K22TREE_SYSCALL, NULL, NULL);  // Should return -EINVAL

    printf("\n=== Test 4: Zero size ===\n");
    test_k22tree(0, 1);

    printf("\n=== Test 5: Fill a value at the end to ensure full execution ===\n");
    int final_ne = 100;
    struct k22info *final_buf = calloc(final_ne, sizeof(struct k22info));
    if (!final_buf) return 1;
    for (int i = 0; i < final_ne; i++) final_buf[i].pid = -1; // αρχικοποίηση
    syscall(K22TREE_SYSCALL, final_buf, &final_ne);
    printf("Final test executed, first pid=%d\n", final_buf[0].pid);
    free(final_buf);

    return 0;
}

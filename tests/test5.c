#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <linux/k22info.h>

#ifndef __NR_k22tree
#define __NR_k22tree 477   // Άλλαξε με τον αριθμό syscall σου
#endif

int main() {
    int count = 10;
    struct k22info *buf = malloc(sizeof(struct k22info) * count);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    printf("Calling k22tree syscall with buffer size %d...\n", count);
	if(!&count){
	printf("Hello\n");
	return 1;
	}
	
    long ret = syscall(__NR_k22tree, buf, &count);
    if (ret < 0) {
        printf("Syscall failed: %ld, errno=%d (%s)\n", ret, errno, strerror(errno));
    } else {
        printf("Syscall succeeded, %d processes returned:\n", count);
        printf("comm, pid, parent_pid, first_child_pid, next_sibling_pid\n");
        for (int i = 0; i < count && i < 5; i++) { // πρώτα 5 για γρήγορη προβολή
            printf("%s, %d, %d, %d, %d\n",
                buf[i].comm,
                buf[i].pid,
                buf[i].parent_pid,
                buf[i].first_child_pid,
                buf[i].next_sibling_pid);
        }
    }

    free(buf);
    return 0;
}

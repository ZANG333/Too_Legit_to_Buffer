#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <linux/k22info.h>



#ifndef K22TREE_SYSCALL_NUM
#define K22TREE_SYSCALL_NUM 477  // Βάλε το νούμερο του syscall σου
#endif

static void try_ptr(struct k22info *buf, int ne, const char *label) {
    errno = 0;
    int ne_copy = ne;
    int ret = syscall(K22TREE_SYSCALL_NUM, buf, &ne_copy);
    if (ret < 0) {
        printf("%-20s -> ret=%d errno=%d (%s)\n", label, ret, errno, strerror(errno));
    } else {
        printf("%-20s -> ret=%d ne=%d\n", label, ret, ne_copy);
    }
}

int main(void) {
    printf("Test invalid buffer pointers for k22tree syscall\n\n");

    /* 1. NULL buffer */
    try_ptr(NULL, 10, "NULL buf");

    /* 2. small/invalid address (almost always unmapped) */
    try_ptr((struct k22info *)0x1234, 10, "0x1234");

    /* 3. unaligned pointer (may still be a bad address) */
    void *p = malloc(sizeof(struct k22info) * 2);
    if (p) {
        /* make an intentionally unaligned pointer inside valid region */
        void *unaligned = (char *)p + 1;
        try_ptr((struct k22info *)unaligned, 2, "unaligned inside heap");
        free(p);
    }

    /* 4. very large address (likely kernel space on 64-bit) */
    try_ptr((struct k22info *)0xffff888012340000ULL, 4, "likely kernel addr");

    /* 5. invalid 'ne' pointer (NULL) */
    errno = 0;
    int ret = syscall(K22TREE_SYSCALL_NUM, malloc(sizeof(struct k22info) * 2), NULL);
    printf("%-20s -> ret=%d errno=%d (%s)\n", "NULL ne", ret, errno, strerror(errno));

    /* 6. valid buffer as control (small) */
    struct k22info *buf = calloc(4, sizeof(*buf));
    if (buf) {
        try_ptr(buf, 4, "valid heap buf");
        free(buf);
    }

    return 0;
}

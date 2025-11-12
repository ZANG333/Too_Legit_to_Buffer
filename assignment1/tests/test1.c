#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    int ret = syscall(477, (char *)0, 0, (char *)0, 0);
    printf("ret: %d\n", ret);
    if (ret < 0)
            perror("syscall error:");
    return 0;
}
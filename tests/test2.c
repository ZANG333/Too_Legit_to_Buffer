#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <linux/k22info.h>

int main(void){
    int count = 500;
    struct k22info *buf = malloc(sizeof(struct k22info) * count);
    
    if (!buf) {
        printf("Memory allocation failed\n");
        return -1;
    }

    int ret = syscall(477, buf, &count);

    printf("System call returned: %d\n", ret);
    printf("Count: %d\n", count);
    
    if (ret < 0) {
        printf("Error: %d\n", errno);
        free(buf);
        return -1;
    }

    printf("#comm,pid,ppid,fcldpid,nsblpid,nvcsw,nivcsw,stime\n");
    for(int i = 0; i < count; i++){  // Χρησιμοποιήστε count, όχι ret
        printf("%s,%d,%d,%d,%d,%ld,%ld,%ld\n", 
            buf[i].comm,           // ΠΡΟΣΟΧΗ: buf[i] όχι buf->
            buf[i].pid,
            buf[i].parent_pid,
            buf[i].first_child_pid,
            buf[i].next_sibling_pid,
            buf[i].nvcsw,
            buf[i].nivcsw,
            buf[i].start_time);
    }

    free(buf);
    return 0;
}

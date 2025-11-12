#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/k22info.h>

int main() {
    printf("=== k22tree Syscall Test ===\n");
    
    // Test 1: NULL pointers (should return EINVAL)
    printf("Test 1: NULL pointers...\n");
    long ret = syscall(477, NULL, NULL);
    printf("Return: %ld, errno: %d (%s)\n", ret, errno, strerror(errno));
    
    // Test 2: Valid arguments
    printf("\nTest 2: Valid arguments...\n");
    int count = 10;
    struct k22info *buf = malloc(sizeof(struct k22info) * count);
    
    if (!buf) {
        printf("Memory allocation failed\n");
        return -1;
    }
    
    ret = syscall(477, buf, &count);
    printf("Return: %ld, errno: %d (%s)\n", ret, errno, strerror(errno));
    printf("Count after syscall: %d\n", count);
    
    if (ret >= 0) {
        printf("✅ SUCCESS! Syscall completed successfully\n");
        printf("Retrieved %d processes\n", count);
        
        // Print first few entries
       if (count > 0) {
            printf("\nFirst 3 processes:\n");
            printf("comm, pid, ppid, fcldpid, nsblpid\n");
            for (int i = 0; i < count && i < 3; i++) {
                printf("%s, %d, %d, %d, %d\n", 
                    buf[i].comm,
                    buf[i].pid, 
                    buf[i].parent_pid,
                    buf[i].first_child_pid,
                    buf[i].next_sibling_pid);
            }
       }
    } else {
        printf("❌ Syscall failed\n");
    }
    
    free(buf); 
   //  Test 3: Small buffer
    printf("\nTest 3: Small buffer (size=1)...\n");
    int small_count = 1;
    struct k22info small_buf;
    
    ret = syscall(477, &small_buf, &small_count);
    printf("Return: %ld, Count: %d\n", ret, small_count);
    
	
    return 0;
}

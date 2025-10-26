#include <stdio.h>
#include <sys/types.h>
#include <linux/k22info.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

int main() {
    printf("Testing if syscall 467 exists...\n");
    
    // Καλούμε το syscall με NULL pointers - θα πρέπει να επιστρέψει EINVAL (-22) αν υπάρχει
    long ret = syscall(477, NULL, NULL);
    
    printf("Syscall 467 returned: %ld\n", ret);
    printf("errno: %d\n", errno);
    
    if (ret == -1 && errno == 38) {
        printf("ERROR: Syscall 467 not implemented (ENOSYS)\n");
        printf("The system call is not compiled into the kernel\n");
    } else if (ret == -1 && errno == 22) {
        printf("SUCCESS: Syscall 467 exists but rejected our NULL arguments (expected)\n");
    } else {
        printf("Unexpected result: return=%ld, errno=%d\n", ret, errno);
    }
    
    return 0;
}

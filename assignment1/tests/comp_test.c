#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/k22info.h>
#include <errno.h>

#define K22TREE_SYSCALL_NUM 477

int main(void)
{

    printf("----------------TEST BAD ADDRESS----------\n");
    struct k22info *buf = (struct k22info *)0x1234; // abs. address 
    int ne = 10;
    
    int ret = syscall(K22TREE_SYSCALL_NUM, buf, &ne);
    if (ret < 0) {
        perror("syscall failed\n");
        printf("Errno should be 14: %d\n",errno);
    } else {
        printf("syscall returned %d processes\n", ret);
    }


    printf("----------------TEST NULL ADDRESS----------\n");
    struct k22info *buf2 = malloc(200*sizeof(struct k22info));
    int ret2 = syscall(K22TREE_SYSCALL_NUM,buf2,NULL);
    if (ret2 < 0) {
        perror("syscall failed\n");
        printf("Errno should be 22: %d\n",errno);
    } else {
        printf("syscall returned %d processes\n", ret2);
    }
    free(buf2);


    printf("----------------TEST VERY LITTLE SIZE----------\n");
    struct k22info *buf3 = malloc(200*sizeof(struct k22info));
    int ne2 = 0;
    int ret3 = syscall(K22TREE_SYSCALL_NUM,buf3,&ne2);
    if (ret3 < 0) {
        perror("syscall failed\n");
        printf("Errno should be 22: %d\n",errno);
    } else {
        printf("syscall returned %d processes\n", ret3);
    }
    free(buf3);

    printf("----------------TEST WITH NE < NOP----------\n");
    struct k22info *buf4 = malloc(200*sizeof(struct k22info));
    int ne3 = 200;
    int ret4 = syscall(K22TREE_SYSCALL_NUM,buf4,&ne3);
    if (ret4 < 0) {
        perror("syscall failed\n");
    } else {
        printf("syscall returned %d processes\n", ret4);
        printf("RET = %d > ne = %d\n",ret4,ne3);
    }
    free(buf4);


    printf("----------------TEST WITH NE > NOP----------\n");
    struct k22info *buf5 = malloc(500*sizeof(struct k22info));
    int ne4 = 500;
    int ret5 = syscall(K22TREE_SYSCALL_NUM,buf5,&ne4);
    if (ret5 < 0) {
        perror("syscall failed\n");
    } else {
        printf("syscall returned %d processes\n", ret5);
        printf("RET = %d\t == \tne = %d\n",ret5,ne4);
    }
    free(buf4);



    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/k22info.h>
int main(void) {

  int ret_val = -3;
  struct k22info *buf = NULL;
  int size_of_buf = 0;

  // test edge cases---------------------------------------
/*
  printf("Test: ne is bigger than the buffer size \n");
  size_of_buf = 600;
  buf = malloc(sizeof(struct k22info) * 1);
  if (!buf) {
    printf(" Malloc problem\n");

  }
  ret_val = syscall(467, buf, &size_of_buf);
  printf("Return value = %d\n", ret_val);

  free(buf);
  buf = NULL;
    

  printf("Do you wanna print the structs inside the buffer? (type 1) \n");
  int x;
  scanf("%d", &x);
  if (x == 0) {
    return 0;
  }
*/
  // test the syscall cases---------------------------------------

  size_of_buf = 500;
  buf = malloc(sizeof(struct k22info) * size_of_buf);
  if (!buf) {
    printf(" Malloc problem\n");
    return 1;
  }

  ret_val = syscall(467, buf, &size_of_buf);
  printf("#comm,pid,ppid,fcldpid,nsblpid,nvcsw,nivcsw,stime\n");
  for (int i = 0; i < ret_val; i++) {

    printf("%s,%d,%d,%d,%d,%lu,%lu,%lu\n", buf[i].comm, buf[i].pid,
           buf[i].parent_pid, buf[i].first_child_pid, buf[i].next_sibling_pid,
           buf[i].nvcsw, buf[i].nivcsw, buf[i].start_time);
  }

    printf("---------------ret_val = %d---------------ne = %d", ret_val,size_of_buf);
  return 0;
}

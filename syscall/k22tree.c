#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/k22info.h>


static int dfs(struct k22info *kbuf, int max_size){
    // Placeholder for DFS implementation
    // This function should populate kbuf with process information
    // and return the number of processes filled in.
    return 0; // Replace with actual number of processes found
}

static int do_k22tree(struct k22info *buf,int *ne){
    
    struct k22info *kbuf;
    int size;
    int ret_val;

    if(!buf || !ne) {
        ret_val =  -EINVAL;  // Invalid argument
        goto out;
    }
    
    if(copy_from_user(&size, ne, sizeof(int))){
        ret_val =  -EFAULT;
        goto out;
    }

    kbuf = kmalloc(size * sizeof(struct k22info), GFP_KERNEL);
    if (!kbuf) {   
        ret_val =  -ENOMEM; // Memory allocation failed
        goto out;
    }
    //lock

    //DFS
    int number_processes = dfs(kbuf,size);

    //unlock
    if(size < number_processes){
        //we should only fill the buf up to size
        goto out;
    }

    //Copy to user space

out:
    if(kbuf)
        kfree(kbuf);
    return ret_val;   
}

SYSCALL_DEFINE2(k22tree,struct k22info __user*, buf, int __user*, ne){
    return do_k22tree(buf, ne);
}
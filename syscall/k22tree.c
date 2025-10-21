#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/k22info.h>

struct info_node{
    struct list_head list;
    struct task_struct *task;
};


static int dfs(struct k22info *kbuf, int max){
    int count = 0;
    int ret_val;
    struct task_struct *task;

    /*Initialize a list*/
    LIST_HEAD(stack);
    
    /*Create the struct with the tasks*/
    struct info_node *root = kmalloc(sizeof(struct info_node), GFP_KERNEL);
    if(!root){
        ret_val = -ENOMEM;
        goto out;
    }

    /*Link the two linked lists*/
    root->task = &init_task;
    list_add(&root->list, &stack);


    /*Then we start the DFS*/

out:
    return ret_val;
}

/*Syscall Implementation*/
static int do_k22tree(struct k22info *buf,int *ne){
    
    struct k22info *kbuf;
    int size;
    int ret_val;
    int number_processes;

    if(!buf || !ne) {
        ret_val =  -EINVAL;  // Invalid argument
        goto out;
    }
    
    /*Copy size from user space*/
    if(copy_from_user(&size, ne, sizeof(int))){
        ret_val =  -EFAULT;
        goto out;
    }

    /*Make sure that the number of entries is valid*/
    if(size < 1){
        ret_val = -EINVAL;
        goto out;
    }

    /*Validate user buffer with access_ok function*/

    kbuf = kmalloc(size * sizeof(struct k22info), GFP_KERNEL);
    if (!kbuf) {   
        ret_val =  -ENOMEM; // Memory allocation failed
        goto out;
    }
    //lock

    //DFS
    number_processes = dfs(kbuf,size);

    //unlock

    /* Copy results to user space */
    if (copy_to_user(buf, kbuf, ret_val * sizeof(struct k22info))) {
        ret_val = -EFAULT;
        goto out;
    }


    ret_val = number_processes;

out:
    if(kbuf)
        kfree(kbuf);
    return ret_val;   
}

SYSCALL_DEFINE2(k22tree,struct k22info __user*, buf, int __user*, ne){
    return do_k22tree(buf, ne);
}
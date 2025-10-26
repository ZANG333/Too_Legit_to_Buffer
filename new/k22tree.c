#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rculist.h>
#include <linux/ktime.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/k22info.h>

struct info_node{
    struct list_head list;
    struct task_struct *task;
};

/*Helper function to find first child*/
static pid_t find_first_child_pid(struct task_struct *task){
    struct task_struct *child;

    list_for_each_entry_reverse(child, &task->children, sibling) {
            return task_pid_nr(child);
    }

   return 0; //no children
}

/* Helper function to find the oldest sibling*/
static pid_t find_next_sibling_pid(struct task_struct *task){
    struct task_struct *sibling_goal;
    struct task_struct *parent ;
    
    /* Init task has no real parent*/
    if(!task->real_parent){
        return 0;
    }

    parent = task->real_parent;

    list_for_each_entry(sibling_goal, &parent->children, sibling) {
        if(sibling_goal != task){
            return task_pid_nr(sibling_goal);
        }
        else{
            break;
        }
    }
    return 0; //no older sibling
}


static int dfs(struct k22info *kbuf, int max){
    int count = 0;
    int ret_val = 0;
    struct task_struct *task;
    struct info_node *curr;

    /*Initialize a list*/
    LIST_HEAD(stack);
    
    /*Create the struct with the tasks*/
    struct info_node *root = kmalloc(sizeof(struct info_node), GFP_ATOMIC);
    if(!root){
        ret_val = -ENOMEM;
        goto leave;
    }

    /* Add the root to the stack*/
    root->task = &init_task;
    INIT_LIST_HEAD(&root->list); 
    list_add(&root->list, &stack);

    read_lock(&tasklist_lock);

    /*Then we start the DFS*/
    while(!list_empty(&stack)){
        
        /*Pop from stack*/
        curr = list_last_entry(&stack, struct info_node, list);
        /*Delete that entry from the list*/
        list_del(&curr->list);


        //If the count > max we break the loop and start a loop with for_each_process to count all the processes
        if(count >= max){
            kfree(curr);
            goto counting;
        }

        /*Fill the buffer*/
        kbuf[count].pid = task_pid_nr(curr->task);
        kbuf[count].parent_pid = task_ppid_nr(curr->task);
        get_task_comm(kbuf[count].comm, curr->task);

        /* Youngest Child*/
        kbuf[count].first_child_pid = find_first_child_pid(curr->task);
        /* Oldest sibling*/
        kbuf[count].next_sibling_pid = find_next_sibling_pid(curr->task);

        /* Context switches */
        kbuf[count].nvcsw = curr->task->nvcsw;
        kbuf[count].nivcsw = curr->task->nivcsw;

         /* Start time */
        kbuf[count].start_time = ktime_get_boottime_ns() - curr->task->start_boottime;

        count++;
        
        /* Push children to stack in reverse order*/
        if (!list_empty(&curr->task->children)) {
            struct task_struct *child;
            
            list_for_each_entry_reverse(child, &curr->task->children, sibling) {
                struct info_node *child_node = kmalloc(sizeof(struct info_node), GFP_ATOMIC);
                if (!child_node) {
                    ret_val = -ENOMEM;
                    kfree(curr);
                    goto free_mem;
                }
                child_node->task = child;
                INIT_LIST_HEAD(&child_node->list);
                list_add(&child_node->list, &stack);
            }
        }
        kfree(curr);
    }
    ret_val = count;
    goto leave;

counting:
    struct task_struct *t;
    count = 0;
    for_each_process(t){
        count++;
    }
    ret_val = count;
free_mem:
    /* Free remaining nodes in the stack */
    while (!list_empty(&stack)) {
        struct info_node *node = list_last_entry(&stack, struct info_node, list);
        list_del(&node->list);
        kfree(node);
    }
leave:
    read_unlock(&tasklist_lock);
    return ret_val;
}

/*Syscall Implementation*/
static int do_k22tree(struct k22info *buf,int *ne){
    
    struct k22info *kbuf;
    int size;
    int ret_val;
    int number_processes;
    int kne;

    if(!buf || !ne) {
        ret_val =  -EINVAL;  // Invalid argument
        goto out;
    }
    
    /* Validate ne*/
    if(!access_ok(ne, sizeof(int))) {
        ret_val = -EFAULT;
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

    /* Validate user buffer */
    if(!access_ok(buf, sizeof(struct k22info) * size)) {
        ret_val = -EFAULT;
        goto out;
    }

    kbuf = kmalloc(size * sizeof(struct k22info), GFP_KERNEL);
    if (!kbuf) {   
        ret_val =  -ENOMEM; // Memory allocation failed
        goto out;
    }

    memset(kbuf, 0, size * sizeof(struct k22info));

    //DFS
    number_processes = dfs(kbuf,size);
    if(number_processes < 0){
        goto out;
    }

    kne = min(number_processes,size);

    /* Copy results to user space */
    if (copy_to_user(buf, kbuf,kne * sizeof(struct k22info))) {
        ret_val = -EFAULT;
        goto out;
    }

    /*Update ne*/
    if (copy_to_user(ne, &kne, sizeof(int))) {
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
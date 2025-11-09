// SPDX-License-Identifier: GPL-2.0

#include <linux/k22info.h>
#include <linux/ktime.h>
#include <linux/rculist.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/bitmap.h>
#include <linux/minmax.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define SLACK 50

/*
 * first_child_pid() - Helper Function that fetched pid of the first child
 * @ task: pointer to the task whose first child we need to get the pid of
 *
 * Context: The function uses no locks and does not sleep
 *
 * Return: The pid of the first child of the given task or 0 if there are
 *         no children
 */
static pid_t find_first_child_pid(struct task_struct *task) {
  struct task_struct *child;

  if (list_empty(&task->children))
    return 0;

  child = list_first_entry(&task->children, struct task_struct, sibling);
  return task_pid_nr(child);
}

/*
 * find_next_sibling_pid() - Helper function to find the pid of the next sibling
 * @ task: Pointer to the task whose first sibling we want to get the pid of
 *
 * Context: The function uses no locks and does not sleep
 *
 * Return: The pid of the next sibling of the given task  or 0 if there are
 *         no siblings.
 */
static pid_t find_next_sibling_pid(struct task_struct *task) {
  struct task_struct *next;

  if (!task->real_parent || list_empty(&task->real_parent->children))
    return 0;

  if (list_is_last(&task->sibling, &task->real_parent->children))
    return 0;

  next = list_next_entry(task, sibling);
  return task_pid_nr(next);
}

/*
 * store_buffer() - Helper function that stores info of a task into the kbuf
 * @ curr: Pointer to the task whose info we want to store
 * @ kbuf: Pointer to the kernel buffer where we want to store the info
 * @ index: Index in the kbuf where we want to store the info
 *
 * Context: The function uses no locks and does not sleep
 */
static void store_buffer(struct task_struct *curr, struct k22info *kbuf, int index) {
  kbuf[index].pid = task_pid_nr(curr);
  kbuf[index].parent_pid = task_ppid_nr(curr);
  get_task_comm(kbuf[index].comm, curr);
  kbuf[index].first_child_pid = find_first_child_pid(curr);
  kbuf[index].next_sibling_pid = find_next_sibling_pid(curr);
  kbuf[index].nvcsw = curr->nvcsw;
  kbuf[index].nivcsw = curr->nivcsw;
  kbuf[index].start_time = curr->start_time;
}

/**
 * traverse_from_root() - Helper function that does a dfs traversal of a tree with 
 *                        the given root
 * @ start: Pointer to the task at the root of the tree
 * @ visited: Pointer to bitmask that keeps track of visited tasks
 * @ kbuf: Pointer to the kernel buffer where we want to store the info
 * @ max: Max number of entries that the kbuf can hold 
 * @ count_total: Total numbers of processes running
 * @ count_stored: Total number of tasks stored in the kbuf buffer
 *
 * This function performs a non recursive depth first search of the task 
 * list using the pointers inside the task struct to traverse the list with
 * respect to parent-child and sibling relashionships. That way we do not need
 * to allocate new buffers for the traversal and storing of the tasks resulting
 * in increased memory efficiency. It stores at most max entities into the kbuf
 * buffer and counts all the processes running at the time
 *
 * Context: The function uses no locks and does not sleep. However it is called by 
 *          another function that already has used a tasklist lock.
 */
static void traverse_from_root(struct task_struct *start,
                               unsigned long *visited,
                               struct k22info *kbuf,
                               int max,
                               int *count_total,
                               int *count_stored)
{
    struct task_struct *curr = start;

    while (curr) {
        pid_t pid = task_pid_nr(curr);

        if (pid >= 0 && pid <= PID_MAX_LIMIT && !test_and_set_bit(pid, visited)) {
            (*count_total)++;
            if (*count_stored < max) {
                store_buffer(curr, kbuf, *count_stored);
                (*count_stored)++;
            }
            if (!list_empty(&curr->children)) {
                curr = list_first_entry(&curr->children, struct task_struct, sibling);
                continue;
            }
        }

        struct task_struct *next = NULL;
        while (curr && !next) {
            if (curr != &init_task && curr->real_parent) {
                if (!list_is_last(&curr->sibling, &curr->real_parent->children)) {
                    next = list_next_entry(curr, sibling);
                }
            }
            
            if (next) {
                break; 
            }
            
            if (curr == &init_task) {
                curr = NULL; 
            } else {
                curr = curr->real_parent;
            }
        }
        curr = next;
    }
}

/**
 * dfs() - Function that traverses the task tree and stored task info 
 * @ kbuf: Pointer to the kernel buffer where we want to store the info
 * @ max:: Max number of entries that the kbuf can hold 
 *
 * This function acesses the task tree and calls other helper functions that
 * perform a non recursive depth first search of the task list using the pointers
 * inside the task struct to traverse the list with respect to parent-child and 
 * sibling relashionships and store their info into the kbuf. After the traversal of 
 * the task tree the function once again counts all the running processes since there 
 * may be some processes that have been detached from the task tree. In case the function
 * finds such tasks they are handled seperately and placed into the end of the kbuf.
 *
 * Context:
 * A read lock is held to guarantee that the accessed task_struct data
 * will not be mutated while DFS traversal is ongoing. It is released
 * after the traversal finishes.
 *
 * Return: The total number of tasks currently running (taking into account the detached ones
 *         if they exist)
 */
static int dfs(struct k22info *kbuf, int max)
{
    unsigned long *visited = bitmap_zalloc(PID_MAX_LIMIT + 1, GFP_KERNEL);
    if (!visited)
        return -ENOMEM;

    int count_total = 0;
    int count_stored = 0;
    struct task_struct *t;

    read_lock(&tasklist_lock);

    traverse_from_root(&init_task, visited, kbuf, max, &count_total, &count_stored);

    for_each_process(t) {
        pid_t pid = task_pid_nr(t);
        if (pid > 0 && pid <= PID_MAX_LIMIT && !test_bit(pid, visited)) {
            count_total++;
            if (count_stored < max) {
                store_buffer(t, kbuf, count_stored);
                count_stored++;
            }
        }
    }

    read_unlock(&tasklist_lock);
    bitmap_free(visited);

    return count_total;
}

/*
 * do_k22tree() - System call that fetches information about running processes
 * @ buf: Pointer to user space buffer that will store info about the processes
 * @ ne: Pointer to user space int that determines how many entities the buf can
 * hold
 *
 * The system call fetches and exposes process-specific information to user
 * space about currently running processes by performing a Depth First Search
 * (DFS) with respect to parent-child and sibling hierarchical relationships.
 * The system call also runs a loop that compares the ammount of entries stored in
 * the kbuf to the total number of running processes to prevent underreporting. If 
 * that would be the case the kbuf is freed and reallocated so that it can account 
 * for the extra processes.
 *
 * The retrieved info is stored in an array of struct k22info elements
 * (see linux/k22info.h), containing:
 * 1. Process name (comm)
 * 2. PID
 * 3. Parent PID
 * 4. First child PID (oldest child)
 * 5. Next sibling PID
 * 6-7. Voluntary and involuntary context switches
 * 8. CPU start time
 *
 * Context:
 * A read lock is held to guarantee that the accessed task_struct data
 * will not be mutated while DFS traversal is ongoing. It is released
 * after the traversal finishes.
 *
 * Return:
 * * ret_val - Total number of processes in the system.
 * * -EFAULT - buf or ne are located in inaccessible user address space.
 * * -EINVAL - buf or ne are NULL or *ne < 1.
 * * -ENOMEM - Memory allocation fails.
 */
static int do_k22tree(struct k22info *buf, int *ne) {
  struct k22info *kbuf = NULL;
  struct task_struct *t;
  int size;
  int processes_before = 0;
  int ret_val = 0;
  int processes_after;
  int kne;
  
   if (!buf || !ne) {
    ret_val = -EINVAL;
    goto out;
  }

  if (copy_from_user(&size, ne, sizeof(int))) {
    ret_val = -EFAULT;
    goto out;
  }

  if (size < 1) {
    ret_val = -EINVAL;
    goto out;
  }

  read_lock(&tasklist_lock);
    for_each_process(t) {
      processes_before++;
    }
  read_unlock(&tasklist_lock);


  for(int attempts = 0;attempts<10 ; attempts++)
  {
    kbuf = kcalloc(processes_before + SLACK, sizeof(struct k22info), GFP_KERNEL);

    if (!kbuf) {
      ret_val = -ENOMEM;
      goto out;
    }

    processes_after = dfs(kbuf,processes_before + SLACK);

    if (processes_after < 0) {
      ret_val = processes_after;
      goto out;
}


    if(processes_after <=  processes_before + SLACK){
      break;
    }
    else{
      if(attempts == 9){
        processes_after = processes_before + SLACK;
        break;
      }
        kfree(kbuf);
      processes_before += 50; 
    }
  }
  kne = min(processes_after,size);

  if (copy_to_user(buf, kbuf, kne * sizeof(struct k22info))) {
    ret_val = -EFAULT;
    goto out;
  }

  if (copy_to_user(ne, &kne, sizeof(int))) {
    ret_val = -EFAULT;
    goto out;
  }

    ret_val = processes_after;

out:
  if(kbuf){
    kfree(kbuf);
  }
    return ret_val;
}

SYSCALL_DEFINE2(k22tree, struct k22info __user *, buf, int __user *, ne) {
  return do_k22tree(buf, ne);
}

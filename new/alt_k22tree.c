// SPDX-License-Identifier: GPL-2.0

#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/rculist.h>
#include <linux/ktime.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/k22info.h>

struct info_node {
	struct list_head list;
	struct task_struct *task;
};

/* Helper function to find first (youngest) child */
static pid_t find_first_child_pid(struct task_struct *task)
{
	struct task_struct *child;

	list_for_each_entry_rcu(child, &task->children, sibling)
		return task_pid_nr(child);

	return 0; /* No children */
}

/* Helper function to find the pid of the next sibling */
static pid_t find_next_sibling_pid(struct task_struct *task)
{
	struct task_struct *next;

	if (!task->real_parent || list_empty(&task->real_parent->children))
		return 0;

	if (list_is_last(&task->sibling, &task->real_parent->children))
		return 0;

	next = list_next_entry(task, sibling);
	return task_pid_nr(next);
}

/*Main Function the program utilizes to traverse the task list depth first*/
static int dfs(struct k22info *kbuf, int max)
{
	int count = 0;
	int ret_val = 0;
	struct info_node *curr;
	bool lock = false;
	LIST_HEAD(stack);

	struct info_node *root = kmalloc(sizeof(*root), GFP_KERNEL);

	if (!root) {
		ret_val = -ENOMEM;
		goto leave;
	}

	root->task = &init_task;
	INIT_LIST_HEAD(&root->list);
	list_add(&root->list, &stack);

	rcu_read_lock();
	lock = true;

	while (!list_empty(&stack)) {
		curr = list_last_entry(&stack, struct info_node, list);
		list_del(&curr->list);

		if (count >= max) {
			kfree(curr);
			goto counting;
		}

		kbuf[count].pid = task_pid_nr(curr->task);
		kbuf[count].parent_pid = task_ppid_nr(curr->task);
		get_task_comm(kbuf[count].comm, curr->task);

		kbuf[count].first_child_pid = find_first_child_pid(curr->task);
		kbuf[count].next_sibling_pid = find_next_sibling_pid(curr->task);

		kbuf[count].nvcsw = curr->task->nvcsw;
		kbuf[count].nivcsw = curr->task->nivcsw;

		kbuf[count].start_time = curr->task->start_time;

		count++;

		{
			struct task_struct *child;

			list_for_each_entry_reverse(child, &curr->task->children, sibling) {
				struct info_node *child_node;

				child_node = kmalloc(sizeof(*child_node), GFP_ATOMIC);
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
{
	struct task_struct *t;

	count = 0;
	for_each_process(t)
		count++;
	ret_val = count;
}

free_mem:
	while (!list_empty(&stack)) {
		struct info_node *node = list_last_entry(&stack, struct info_node, list);

		list_del(&node->list);
		kfree(node);
	}

leave:
	if (lock)
		rcu_read_unlock();
	return ret_val;
}

/**
 * k22tree() - System call that fetches information about running processes
 * @ buf: Pointer to user space buffer that will store info about the processes
 * @ ne: Pointer to user space int that determines how many entities the buf can hold
 * 
 * The system call fetches and exposes process-specific0 information to user space
 * about current running processes by accessing the init_task and then doing a
 * depth first search (DFS) with respect to parent-child and sibling hirerchical
 * process relationships. The exposed iformation is stored in an array with variables
 * of type struct k22info (read more on the linux/k22info.h) which store the following:
 * 1. Name of process executable, 2. Pid, 3. parent Pid, 4. Pid of youngest child,
 * 5. Pid of oldest sibling (next one), 6-7. Voluntary and Involuntary context switches
 * 8. CPU uptime
 *
 * Context: The system call utilizes locks to ensure that the process data that the 
 *          system call wants to access can not and will not be mutated. These locks
 *          are released when the DFS concludes.
 * Return: 
 * * ret_val -Total number of processes running. This must 
 *         not be confused with the ne argument which dictates how namy processes the
 *         user space buf can hold.
 * * EFAULT -If buf or ne are outside the accessible adress space
 * * EINVAL -IF buf or ne are NULL or the number of entities is less than 1   
 */
static int do_k22tree(struct k22info *buf, int *ne)
{
	struct k22info *kbuf = NULL;
	int size;
	int ret_val = 0;
	int number_processes;
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

	kbuf = kmalloc_array(size, sizeof(struct k22info), GFP_KERNEL);
	if (!kbuf) {
		ret_val = -ENOMEM;
		goto out;
	}

	memset(kbuf, 0, size * sizeof(struct k22info));

	number_processes = dfs(kbuf, size);
	if (number_processes < 0) {
		ret_val = number_processes;
		goto out;
	}

	kne = min(number_processes, size);

	if (copy_to_user(buf, kbuf, kne * sizeof(struct k22info))) {
		ret_val = -EFAULT;
		goto out;
	}

	if (copy_to_user(ne, &kne, sizeof(int))) {
		ret_val = -EFAULT;
		goto out;
	}

	ret_val = number_processes;

out:
	kfree(kbuf);
	return ret_val;
}

SYSCALL_DEFINE2(k22tree, struct k22info __user *, buf, int __user *, ne)
{
	return do_k22tree(buf, ne);
}

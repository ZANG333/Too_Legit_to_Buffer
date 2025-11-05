// SPDX-License-Identifier: GPL-2.0

#include <linux/k22info.h>
#include <linux/ktime.h>
#include <linux/rculist.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/*
 * struct info_node - Helper struct used to implement stack for dfs
 * @ list: pointer to the next member of the stack
 * @ task: pointer to the task stored in current node
 */
struct info_node {
	struct list_head list;
	struct task_struct *task;
};

/*
 * first_child_pid() - Helper Function that fetched pid of the first child
 * @ task: pointer to the task whose first child we need to get the pid of
 *
 * Context: The function uses no locks and does not sleep
 *
 * Return: The pid of the first child of the given task or 0 if there are
 *         no children
 */
static pid_t find_first_child_pid(struct task_struct *task)
{
	struct task_struct *child;

	list_for_each_entry(child, &task->children, sibling) {
		return task_pid_nr(child);
	}

	return 0;
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

/*
 * dfs() - Function that performs a dfs of the task list
 * @ kbuf: pointer to a kernel allocated buffer that will store the info
 *				 from the nodes that we traverse
 * @ max: Maximum number of tasks that can fit into the kbuf
 *
 * This function uses a stack to perform a non recursive depth first search
 * of the task list with respect to parent child and sibling relashionships.
 * The traversed task get some of the info saved in the kbuf in variables of
 * type k22info (see linux/k22info.h). if there are more tasks (processes)
 * running than the kbuf can hold (max < num_processes) the function copies
 * as many as possible into the kbuf and just counts the rest
 *
 * Return:
 * * ret_val - Number of running processes (not necessarily as many as the kbuf
 * has)
 * * -ENOMEM - Memory allocation has failed
 */
static int dfs(struct k22info *kbuf, int max)
{
	int count = 0;
	int ret_val = 0;
	struct info_node *curr;
	struct info_node *root;

	root = kmalloc(sizeof(*root), GFP_KERNEL);
	if (!root) {
		ret_val = -ENOMEM;
		goto leave;
	}

	LIST_HEAD(stack);

	root->task = &init_task;
	INIT_LIST_HEAD(&root->list);
	list_add(&root->list, &stack);

	read_lock(&tasklist_lock);
	while (!list_empty(&stack) && count < max) {

		curr = list_last_entry(&stack, struct info_node, list);
		list_del(&curr->list);

		kbuf[count].pid = task_pid_nr(curr->task);
		kbuf[count].parent_pid = task_ppid_nr(curr->task);
		get_task_comm(kbuf[count].comm, curr->task);
		kbuf[count].first_child_pid = find_first_child_pid(curr->task);
		kbuf[count].next_sibling_pid = find_next_sibling_pid(curr->task);
		kbuf[count].nvcsw = curr->task->nvcsw;
		kbuf[count].nivcsw = curr->task->nivcsw;
		kbuf[count].start_time = curr->task->start_time;
		count++;

		struct task_struct *child;
		list_for_each_entry_reverse(child, &curr->task->children, sibling) {
			struct info_node *child_node;

			child_node = kmalloc(sizeof(*child_node), GFP_ATOMIC);
			if (!child_node) {
				ret_val = -ENOMEM;
				kfree(curr);
				goto leave;
			}

			child_node->task = child;
			INIT_LIST_HEAD(&child_node->list);
			list_add_tail(&child_node->list, &stack);
		}

		kfree(curr);
	}

	ret_val = count;

leave:
	read_unlock(&tasklist_lock);

	while (!list_empty(&stack)) {
		struct info_node *node = list_last_entry(&stack, struct info_node, list);
		list_del(&node->list);
		kfree(node);
	}

	return ret_val;
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
static int do_k22tree(struct k22info *buf, int *ne)
{
	struct k22info *kbuf = NULL;
	struct task_struct *tmp;
	int size;
	int ret_val = 0;
	int processes_written;
	int process_count;
	int kbuf_size;

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
	for_each_process(tmp) {
		process_count++;
	}
	read_unlock(&tasklist_lock);

	kbuf_size = min(size, process_count + 20);
	kbuf = kcalloc(kbuf_size, sizeof(struct k22info), GFP_KERNEL);
	if (!kbuf) {
		ret_val = -ENOMEM;
		goto free_mem;
	}

	processes_written = dfs(kbuf, kbuf_size);
	if (processes_written < 0) {
		ret_val = processes_written;
		goto free_mem;
	}

	if (copy_to_user(buf, kbuf, processes_written * sizeof(struct k22info))) {
		ret_val = -EFAULT;
		goto free_mem;
	}

	if (copy_to_user(ne, &processes_written, sizeof(int))) {
		ret_val = -EFAULT;
		goto free_mem;
	}

	ret_val = max(processes_written, process_count);

free_mem:
	kfree(kbuf);
out:
	return ret_val;
}

SYSCALL_DEFINE2(k22tree, struct k22info __user *, buf, int __user *, ne) {
	return do_k22tree(buf, ne);
}

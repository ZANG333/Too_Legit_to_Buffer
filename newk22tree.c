#include <linux/k22info.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/errno.h>

struct stack_node{
	struct task_struct *task; 
	struct list_head list;
};


static int do_k22tree(struct k22info *buf, int *ne)
{
	int size;
	int count = 0;
	int ret_code;
	struct k22info *kbuf;
	struct stack_node *node;
	struct stack_node *new;
	struct list_head stack_head;


	if(copy_from_user(&size, ne, sizeof(size)))return -1;

	kbuf = kmalloc(sizeof(struct k22info)*size, GFP_KERNEL);

	INIT_LIST_HEAD(&stack_head);

	new = kmalloc(sizeof(struct stack_node), GFP_KERNEL);
	INIT_LIST_HEAD(&new->list);

	list_add(&new->list, &stack_head);

	do{
		
		struct list_head *top = stack_head.next;

		
		list_del(top);
		node = list_entry(top, struct stack_node, list);


		struct task_struct *cur;
		list_for_each_entry_reverse(cur, &node->task->children, children){

			
			new = kmalloc(sizeof(struct stack_node), GFP_KERNEL);
			new->task = cur;
			INIT_LIST_HEAD(&new->list);
			
			list_add(&new->list, &stack_head);
		}
		
		struct task_struct *tmp_task;
		struct task_struct *tmp_child;

		tmp_task = node->task;

		tmp_child = list_first_entry(&tmp_task->children, struct task_struct, children);
		kbuf[count].first_child_pid = tmp_child->pid;

		tmp_child = list_last_entry(&tmp_task->sibling, struct task_struct, children);
		kbuf[count].next_sibling_pid = tmp_child->pid;

		strcpy(kbuf[count].comm, tmp_task->comm);
		kbuf[count].pid = tmp_task->pid;
		kbuf[count].parent_pid = tmp_task->parent->pid;
		kbuf[count].nvcsw = tmp_task->nvcsw;
		kbuf[count].nivcsw = tmp_task->nivcsw;
		kbuf[count].start_time = tmp_task->start_time;
		count++;

		kfree(node);


	} while(!list_empty(&stack_head));

	ret_code = count;

	if(copy_to_user(buf, kbuf, count*sizeof(struct k22info)))return -1;



	return ret_code;
}

SYSCALL_DEFINE2(k22tree, struct k22info __user *, buf, int __user *, ne)
{
	return do_k22tree(buf, ne);
}

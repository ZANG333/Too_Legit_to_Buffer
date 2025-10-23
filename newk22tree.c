#include <linux/k22info.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/printk.h>

struct stack_node{
	struct task_struct *task; 
	struct list_head list;
};


static int do_k22tree(struct k22info *buf, int *ne)
{
	int size;
	int count = 0;
	int return_code;
	struct k22info *kbuf;
	struct stack_node *node;
	struct stack_node *new;
	struct list_head stack_head;
	spinlock_t lock;

	pr_info("k22tree DEBUG: 1\n");
	if (copy_from_user(&size, ne, sizeof(size))) {
		return_code = -EFAULT;
		goto out;
	}

	pr_info("k22tree DEBUG: 2\n");
	kbuf = kmalloc(sizeof(struct k22info)*size, GFP_KERNEL);
	if (!kbuf) {
		return_code = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&stack_head);

	new = kmalloc(sizeof(struct stack_node), GFP_KERNEL);
	if (!new) {
		return_code = -ENOMEM;
		goto free_kbuf;
	}

	INIT_LIST_HEAD(&new->list);
	new->task = &init_task;

	pr_info("k22tree DEBUG: 3\n");
	list_add(&new->list, &stack_head);

	spin_lock_init(&lock);

	pr_info("k22tree DEBUG: 4\n");
	do{
		
		pr_info("k22tree DEBUG: 5\n");
		struct list_head *top = stack_head.next;

		
		list_del(top);
		node = list_entry(top, struct stack_node, list);
		pr_info("k22tree DEBUG address %p\n",node);


		pr_info("k22tree DEBUG: 5.1\n");
		struct task_struct *cur;

		int debug_test_count = 0;
		list_for_each_entry_reverse(cur, &node->task->children, children){

			
			new = kmalloc(sizeof(struct stack_node), GFP_KERNEL);
			if (!new) {
				return_code = -ENOMEM;
				goto free_stack;
			}

			new->task = cur;
			INIT_LIST_HEAD(&new->list);
			
			list_add(&new->list, &stack_head);

			debug_test_count++;
			
		}
		pr_info("k22tree DEBUG count %d\n",debug_test_count);
		
		struct task_struct *tmp_task;
		struct task_struct *tmp_child;
		tmp_task = node->task;

		spin_lock(&lock);

		pr_info("k22tree DEBUG: 5.2\n");
		tmp_child = list_first_entry(&tmp_task->children, struct task_struct, children);
		kbuf[count].first_child_pid = tmp_child->pid;

		tmp_child = list_last_entry(&tmp_task->sibling, struct task_struct, children);
		kbuf[count].next_sibling_pid = tmp_child->pid;

		pr_info("k22tree DEBUG: 5.3\n");
		strcpy(kbuf[count].comm, tmp_task->comm);
		kbuf[count].pid = tmp_task->pid;
		kbuf[count].parent_pid = tmp_task->parent->pid;
		kbuf[count].nvcsw = tmp_task->nvcsw;
		kbuf[count].nivcsw = tmp_task->nivcsw;
		kbuf[count].start_time = tmp_task->start_time;
		count++;

		spin_unlock(&lock);

		kfree(node);

		int res = list_empty(&stack_head);
		pr_info("k22tree DEBUG: 5.4%d \n",res);


	} while(!list_empty(&stack_head));

	return_code = count;

	pr_info("k22tree DEBUG: 6\n");
	if (copy_to_user(buf, kbuf, count*sizeof(struct k22info))) {
		return_code = -EFAULT;
		goto free_stack;
	}

	pr_info("k22tree DEBUG: 7\n");


	return return_code;

free_stack:
	while (!list_empty(&stack_head)) {

		struct list_head *tmp = stack_head.next;
		list_del(tmp);
		kfree(tmp);
	}

free_kbuf:
	kfree(kbuf);

out:
	return return_code;
}

SYSCALL_DEFINE2(k22tree, struct k22info __user *, buf, int __user *, ne)
{
	return do_k22tree(buf, ne);
}

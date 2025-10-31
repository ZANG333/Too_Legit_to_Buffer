# K22tree.c

This syscall traverses the complete process tree of the kernel and exposes process specific information to user-space (which is not allowed through traditional means), in a Depth-First Search (DFS) order with respect to parent-child and sibling relationships. Some of this exposed info refers to a process' voluntary and involuntary context switches (nvcsw and nivcsw) and uptime since system boot. These data are quite interesting since we can deduce some of the processes characteristics judging by these numbers.

## Processes with high nivcsw number

So what can we assume for a program whose process has a high number of involuntary context switches. For starters an involuntary context switch is when the OS takes the processor away from a process forcibly. This can happen when the process exceeds the time quota (preemption), when hardware interupts are handled, in page faults and exeptions or when a process with more priority wants to utilize the CPU. With this in mind we can assume that such a program would run multiple perhaps lenghty loops that may cause it to get preempted and is not of vital importance (low priority). An example of such a program would be a file enryptor since it would run a loop on evey byte (for example) of the file to encrypt using complex mathematical operations. It also is of low priority since it is a task that can be delayed for a bit without causing issues letting more important processes into the CPU. And lastly suppose the encoder accesses a memory-mapped input buffer which is paged out we would run into a page fault that should be immediately resolved.    

## Processes with high nvcsw number

Judging by what makes a process to be involuntarily descheduled we can assume that a program whose process has a high amount of nvcsw finishes whatever it is doing within the time quota set by the timer implementing preemption and then knows that it must wait on some I/O operation or something else done by another process or thread. Thus it willingly uses a primitive like wait or sleep to let the required operation be completed. A program whose process may behave like this is a web browser that requires user input to proceed and can do nothing else without it.

## Process uptime

When calling the ``k22tree()`` system call we can also observe that some processes have similar extremely high running time especially when compared to some of the other processes.This time also aligns quite conveniently with the system uptime. We can safely assume that these processes belong to kernel-space programs which are vital for the OS that start automatically during booting of the system or right after the boot ends. Under closer observation we can also see that these processes also have small pid compared to others something that also confirms that they were created earlier than the other ones. 

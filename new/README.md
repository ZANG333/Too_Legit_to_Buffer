# K22tree.c

This syscall traverses the complete process tree of the kernel and exposes process specific information to user-space (which is not allowed through traditional means), in a Depth-First Search (DFS) order with respect to parent-child and sibling relationships. Some of this exposed info refers to a process' voluntary and involuntary context switches (nvcsw and nivcsw) and uptime since system boot. These data are quite interesting since we can deduce some of the processes characteristics judging by these numbers.

## Processes with high nivcsw number

So what can we assume for a program whose process has a high number of involuntary context switches. For starters an involuntary context switch is when the OS takes the processor away from a process forcibly. This can happen when the process exceeds the time quota (preemption). This is really common with programs whose processes require lots of time-costly I/O operations like for example disk access or waiting for resourses from the network. With this info we can conclude that such a process belongs to a program that is running for a relatively long time and performs a lot of I/O operations and is not of vital importance to the CPU. For example that program may be some sort of database that requests lots of disk accesses which is an I/O operation that takes a lot of time (~100 CPU cycles).

## Processes with high nvcsw number

Judging by what makes a process to be involuntarily descheduled we can assume that a program whose process has a high amount of nvcsw finishes whatever it is doing within the time quota set by the timer implementing preemption and then knows that it must wait on some I/O operation or something else done by another process or thread. Thus it willingly uses a primitive like wait or sleep to let the required operation be completed. A program whose process may behave like this is a web browser that requires user input to proceed and can do nothing else without it.

## Process uptime

When calling the ``k22tree()`` system call we can also observe that some processes have similar extremely high running time especially when compared to some of the other processes.This time also aligns quite conveniently with the system uptime. We can safely assume that these processes belong to kernel-space programs which are vital for the OS that start automatically during booting of the system or right after the boot ends. Under closer observation we can also see that these processes also have small pid compared to others something that also confirms that they were created earlier than the other ones. 

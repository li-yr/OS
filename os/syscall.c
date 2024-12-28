#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"
#include "task.h"
uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz) // TODO: implement sys_gettimeofday in pagetable. (VA to PA)
{
	// YOUR CODE


	/* The code in `ch3` will leads to memory bugs*/
	TimeVal *val_temp;
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	val_temp->sec = cycle / CPU_FREQ;
	val_temp->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, (uint64)val, (char *)&val_temp,sizeof(*val));
	return 0;
}

uint64 sys_sbrk(int n)
{
	uint64 addr;
        struct proc *p = curr_proc();
        addr = p->program_brk;
        if(growproc(n) < 0)
                return -1;
        return addr;	
}

uint64 sys_task_info(TaskInfo *ti){
	// YOUR CODE
	TaskInfo ti_temp;
	ti_temp.status = Running;
	uint64 cycle = get_cycle();
	uint64 now = (cycle) * 1000 / CPU_FREQ;
	ti_temp.time = now - curr_proc()->starttime;
	memmove(ti_temp.syscall_times, curr_proc()->syscall_times, sizeof(curr_proc()->syscall_times));
	copyout(curr_proc()->pagetable, (uint64)ti, (char *)&ti_temp,sizeof(*ti));
	return 0;
}


uint64 sys_mmap(void *addr, unsigned long long len, int port, int flag, int fd){
	debugf("somw");
	flag = 0;
	fd = 0;
	if ((port & ~0x7) != 0||(port & 0x7) == 0) {
		// printf("port input error");
		return -1;
	}
	if (((uint64)addr & (PAGE_SIZE - 1)) != 0) {
		return -1;
	}
	len = PGROUNDUP(len);
	uint64 end = (uint64)addr + len;
	pagetable_t pg = curr_proc()->pagetable;
	for (uint64 vaddr = (uint64)addr; vaddr != end; vaddr += PAGE_SIZE) {
		void *paddr = kalloc();
		if (paddr == 0) {
			printf("mmap physical memory is not enough!");
			return -1;
		}
		mappages(pg, vaddr, PAGE_SIZE, (uint64)paddr, (port << 1) | PTE_U);
		if(flag != 0){
			printf("wa");
			return -1;
		}
		
	}
	return 0;
}

uint64 sys_munmap(void *addr, unsigned long long len, int port, int flag, int fd){
	flag = 0;
	fd = 0;
	if ((port & ~0x7) != 0||(port & 0x7) == 0) {
		panic("port input error");
		return -1;
	}
	len = PGROUNDUP(len);
	uint64 end = (uint64)addr + (uint64)len;
	pagetable_t pg = curr_proc()->pagetable;
	for (uint64 vaddr = (uint64)addr; vaddr != end; vaddr += PAGE_SIZE) {
		uint64 pa = walkaddr(pg, vaddr);
		if (pa == 0) {
			panic("sys_munmap one page is not mapped!");
			return -1;
		}
		uvmunmap(pg, vaddr, 1, 1);
	}
	return 0;
}
// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if(id <= MAX_SYSCALL_NUM){
		curr_proc()->syscall_times[id] ++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_sbrk:
		ret = sys_sbrk(args[0]);
		break;
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap((void *)args[0], (unsigned long long)args[1], (int)args[2],(int)args[3], (int)args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap((void *)args[0], (uint64)args[1], (int)args[2],(int)args[3], (int)args[4]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}

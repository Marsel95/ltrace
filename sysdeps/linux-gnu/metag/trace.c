/*
 * This file is part of ltrace.
 *
 * Copyright (C) 2013 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <linux/uio.h>
#include <asm/ptrace.h>

#include "proc.h"
#include "common.h"

void get_arch_dep(struct process *proc)
{

}

int syscall_p(struct process *proc, int status, int *sysnum)
{
	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		struct user_gp_regs regs;
		struct iovec iov;

		/* get GP registers */
		iov.iov_base = &regs;
		iov.iov_len = sizeof(regs);
		if (ptrace(PTRACE_GETREGSET, proc->pid, NT_PRSTATUS,
			   (long)&iov))
			return -1;

		/* fetch the SWI instruction */
		unsigned int insn = ptrace(PTRACE_PEEKTEXT, proc->pid, regs.pc,
					   0);
		*sysnum = regs.dx[0][1];

		if (insn != 0xAF440001) {
			/* check if we're returning from the system call */
			insn = ptrace(PTRACE_PEEKTEXT, proc->pid, regs.pc - 4,
				      0);
			if (insn == 0xAF440001) {
				return 2;
			}

			return 0;
		}

		if (*sysnum >= 0) {
			return 1;
		}
	}
	return 0;
}

long gimme_arg(enum tof type, struct process *proc, int arg_num, struct arg_type_info *info)
{
	long ret;
	struct user_gp_regs regs;
	struct iovec iov;

	/* get GP registers */
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	if (ptrace(PTRACE_GETREGSET, proc->pid, NT_PRSTATUS, (long)&iov))
		return 0;

	debug(2, "type %d arg %d arg",type, arg_num);
	if (type == LT_TOF_FUNCTION || type == LT_TOF_SYSCALL) {
		if (arg_num < 6) {
			/* Args go backwards starting from D1Ar1 (D1.3) */
			ret = ((unsigned long *)&regs.dx[3][1])[-arg_num];
			debug(2,"ret = %#lx",ret);
			return ret;
		} else {
			return 0;
		}
	}
	if (arg_num >= 0) {
		fprintf(stderr,"args on return?");
	}
	if (type == LT_TOF_FUNCTIONR || type == LT_TOF_SYSCALLR) {
		return regs.dx[0][0]; /* D0Re0 (D0.0) */
	}

	fprintf(stderr, "gimme_arg called with wrong arguments\n");

	return 0;
}

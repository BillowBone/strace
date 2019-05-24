/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** parent.c
*/

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/reg.h>
#include <stdio.h>
#include <signal.h>
#include "my_strace.h"
#include "my_syscalls.h"

void get_registers_tab(struct user_regs_struct regs, unsigned long long tab[6])
{
    tab[0] = regs.rdi;
    tab[1] = regs.rsi;
    tab[2] = regs.rdx;
    tab[3] = regs.r10;
    tab[4] = regs.r8;
    tab[5] = regs.r9;
}

int get_syscalls_args(pid_t my_pid, long opcode)
{
    struct user_regs_struct regs;
    unsigned long long registers[6];

    ptrace(PTRACE_GETREGS, my_pid, NULL, &regs);
    printf("%s(", my_syscalls[opcode].name);
    get_registers_tab(regs, registers);
    for (int i = 0; i < 6; i++) {
        if (my_syscalls[opcode].args[i] == INT && string_option(0) != 0)
            printf("%d", registers[i]);
        else if (my_syscalls[opcode].args[i] != NONE)
            printf("0x%x", registers[i]);
        if (i != 5 && my_syscalls[opcode].args[i + 1] != NONE)
            printf(", ");
    }
    return (1);
}

int get_return_value(pid_t my_pid, long opcode)
{
    long rax = 0;
    void *raxptr = NULL;

    if (opcode != 9 && string_option(0) == 0) {
        rax = ptrace(PTRACE_PEEKUSER, my_pid, 8 * RAX, NULL);
        printf(") = 0x%x\n", rax);
    } else if (opcode != 9 && string_option(0) != 0) {
        rax = ptrace(PTRACE_PEEKUSER, my_pid, 8 * RAX, NULL);
        printf(") = %d\n", rax);
    } else {
        raxptr = (void *)ptrace(PTRACE_PEEKUSER, my_pid, 8 * RAX, NULL);
        printf(") = %p\n", raxptr);
    }
    return (0);
}

void syscall_in_out(pid_t my_pid, long opcode)
{
    static int syscall = 0;

    if (syscall == 0) {
        syscall = get_syscalls_args(my_pid, opcode);
    } else {
        syscall = get_return_value(my_pid, opcode);
    }
}

void strace(pid_t my_pid)
{
    int status = 0;
    long opcode = 0;
    int syscall = 0;
    int ret = 0;

    while (1) {
        wait(&status);
        if (WIFEXITED(status))
            break;
        opcode = ptrace(PTRACE_PEEKUSER, my_pid, 8 * ORIG_RAX, NULL);
        if (opcode >= 0 && opcode <= 313) {
            syscall_in_out(my_pid, opcode);
        }
        ptrace(PTRACE_SINGLESTEP, my_pid, NULL, SIGSTOP);
    }
    ret = WEXITSTATUS(status);
    printf("exit_group(%d) = ?\n", ret);
    printf("+++ exited with %d +++\n", ret);
}
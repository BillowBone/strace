/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** pid.c
*/

#include <unistd.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include "my_strace.h"

void my_pid(void)
{
    pid_t my_pid = save_pid(NULL);

    if (ptrace(PTRACE_ATTACH, my_pid, NULL, NULL) == -1)
        exit(84);
    strace(my_pid);
}

/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** fork.c
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "my_strace.h"

void my_fork(char *program)
{
    char **args = calloc(2, sizeof(char *));
    pid_t my_pid = fork();

    args[0] = strdup("");
    args[1] = NULL;
    if (my_pid == 0) {
        if (ptrace(PT_TRACE_ME, 0, NULL, NULL) == -1)
            exit(84);
        if (execv(program, args) == -1)
            exit(84);
    } else {
        strace(my_pid);
    }
    free(args[0]);
    free(args[1]);
    free(args);
}
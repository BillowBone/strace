/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** save_pid.c
*/

#include <unistd.h>
#include <stdlib.h>

int save_pid(char *str_pid)
{
    static int pid = 0;

    if (str_pid != NULL)
        pid = atoi(str_pid);
    return (pid);
}
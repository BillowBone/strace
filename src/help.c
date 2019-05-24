/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** help.c
*/

#include <stdio.h>
#include "my_strace.h"

void display_help(void)
{
    printf("USAGE: ./strace [-s] [-p <pid>|<command>]\n");
}
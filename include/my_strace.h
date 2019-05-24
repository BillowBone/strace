/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** my_strace.h
*/

#ifndef MY_STRACE_H_
    #define MY_STRACE_H_

#include <sys/types.h>

void display_help(void);
int save_command(int index);
int save_mode(int opt);
int save_pid(char *str_pid);
void manage_errors(int argc, char *argv[]);
void my_fork(char *program);
void my_pid(void);
int string_option(int opt);
void strace(pid_t my_pid);

#endif /* !MY_STRACE_H_ */

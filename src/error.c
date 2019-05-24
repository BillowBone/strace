/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** error.c
*/

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include "my_strace.h"

void process_pid(char *argv[], int index)
{
    if (!argv[index])
        exit(84);
    for (int i = 0; argv[index][i] != 0; i++) {
        if (argv[index][i] < 48 || argv[index][i] > 57)
            exit(84);
    }
    save_mode(2);
    save_pid(argv[index]);
}

void check_command(char *command)
{
    int fd = open(command, O_RDONLY);

    if (fd == -1) {
        printf("strace: Can't stat '%s': No such file or directory\n");
        exit(84);
    }
    save_mode(1);
}

int check_flag(char *arg)
{
    if (strlen(arg) < 2)
        exit(84);
    if (arg[0] == '-' && arg[1] != 's')
        exit(84);
    if (arg[0] == '-' && arg[1] == 's') {
        string_option(1);
        return (1);
    }
    return (0);
}

void manage_errors(int argc, char *argv[])
{
    if (argc == 1) {
        display_help();
        exit(84);
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            display_help();
            exit(0);
        } else if (strcmp(argv[i], "-p") == 0) {
            process_pid(argv, i + 1);
            i++;
            continue;
        } else if (check_flag(argv[i]) == 1) {
            continue;
        } else {
            check_command(argv[i]);
            save_command(i);
        }
    }
}
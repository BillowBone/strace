/*
** EPITECH PROJECT, 2019
** epitech
** File description:
** main
*/

#include "my_strace.h"

int main(int argc, char *argv[])
{
    manage_errors(argc, argv);
    if (save_mode(0) == 1)
        my_fork(argv[save_command(0)]);
    else
        my_pid();
    return (0);
}

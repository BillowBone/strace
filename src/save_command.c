/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** save_command.c
*/

int save_command(int index)
{
    static int index_command = 0;

    if (index != 0)
        index_command = index;
    return (index_command);
}
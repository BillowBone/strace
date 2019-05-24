/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** string_option.c
*/

int string_option(int opt)
{
    static int string = 0;

    if (opt != 0)
        string++;
    return (string);
}
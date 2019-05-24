/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** save_mode.c
*/

int save_mode(int opt)
{
    static int mode = 0;
    static int visits = 0;

    if (opt != 0 && visits == 0)
        mode = opt;
    visits++;
    return (mode);
}
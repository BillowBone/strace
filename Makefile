##
## EPITECH PROJECT, 2019
## PSU - Instrumentation - strace
## File description:
## Makefile
##

SRC	=	./src/main.c	\
		./src/strace.c	\
		./src/fork.c	\
		./src/help.c	\
		./src/error.c	\
		./src/save_command.c	\
		./src/save_mode.c	\
		./src/save_pid.c	\
		./src/pid.c	\
		./src/string_option.c	\

OBJ	=	$(SRC:.c=.o)

CFLAGS	=	-I./include/

NAME	=	strace

all:	$(NAME)

$(NAME):	$(OBJ)
		gcc $(OBJ) $(CFLAGS) -o $(NAME)

clean:
		rm -f $(OBJ)

fclean:	clean
		rm -f $(NAME)

re:		fclean all

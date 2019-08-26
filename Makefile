NAME = ft_ssl

CFILES = main.c ft_md5.c parse.c helpers.c rounds.c hash.c printfiles.c

FLAGS = -Wall -Werror -Wextra 
# -g -fsanitize=address

LIBFT = final-libft

GCC = gcc

all: $(NAME)

$(NAME):
	@echo "\033[32mCompiling files . . .\033[0m"
	@make -C $(LIBFT)
	$(GCC) $(FLAGS) $(CFILES) -L $(LIBFT) -lft -o $(NAME)

clean:
	@echo "\033[32mCleaning .\033[0m"
	@rm -rf $(NAME)
	@make clean -C $(LIBFT)

fclean: clean
	@echo "\033[32mClean more . .\033[0m"
	@make fclean -C $(LIBFT)

re: fclean all

.PHONY: clean fclean all re
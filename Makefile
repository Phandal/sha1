all:
	clang -o hash -Wall -Werror -Wextra -g src/*.c

clean:
	rm -rf hash

.PHONY: clean

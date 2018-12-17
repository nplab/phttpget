CFLAGS= -O2 -std=c99 -pedantic -Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wunreachable-code -Winit-self -g

phttpget: phttpget.c
	$(CC) $(CFLAGS) -o phttpget phttpget.c

clean:
	rm phttpget

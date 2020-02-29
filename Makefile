all:
	gcc -Wall -g -rdynamic -O3 tinflate.c -o gzip-random-seek

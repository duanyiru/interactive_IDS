main: main.o filter.o sniffer.o
	gcc -Wall -Werror filter.o main.o sniffer.o -g -o ids -lip4tc -lip6tc -liptc -lpcap -ldl

sniffer.o: sniffer.c sniffer.h filter.h
	gcc -Wall -Werror sniffer.c -g -c -lip4tc -lip6tc -liptc -lpcap -ldl

filter.o: filter.c filter.h 
	gcc filter.c -g -c -lip4tc -lip6tc -liptc -lpcap -ldl

main.o: main.c main.h
	gcc -Wall -Werror main.c -g -c

clean:
	rm *.o ids

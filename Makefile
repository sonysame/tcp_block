all : test

test: main.o
	g++ -g -o test main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f test
	rm -f *.o



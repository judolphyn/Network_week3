all: pcap-test

pcap-test: main.o headers.h
	g++ -o pcap-test main.o -lpcap

main.o: main.cpp headers.h
	g++ -c -o main.o main.cpp 

clean:
	rm -f pcap-test main.o


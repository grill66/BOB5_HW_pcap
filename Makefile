pcap: pcap.o
	gcc -o pcap pcap.o -lpcap

pcap.o: pcap.c
	gcc -o pcap.o -c pcap.c

clean:
	rm -f ./*.o

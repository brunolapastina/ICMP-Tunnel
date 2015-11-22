CFLAGS=-Wall -fPIC -g

LIBS=-lcrypto -lpthread

all:
	$(CXX) $(CFLAGS) -I./ icmp_server.cpp -o icmp_server $(LIBS)
	$(CXX) $(CFLAGS) -I./ icmp_client.cpp CICMPExchangeClient.cpp -o icmp_client $(LIBS)

clean:
	rm -rf icmp_server
	rm -rf icmp_client
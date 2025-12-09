SRCS += iso14229.c main.c
HDRS += iso14229.h
TARGET = doip_client
CFLAGS = -DUDS_TP_DOIP=1 -DUDS_CONFIG_LOG_COLORS=1 -DUDS_LOG_LEVEL=UDS_LOG_VERBOSE -g

all: $(SRCS) $(HDRS) doip_server.c
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

server: doip_server.c doip_example.c
	$(CC) doip_server.c doip_example.c -o doip_server

clean:
	rm -f $(TARGET) doip_server

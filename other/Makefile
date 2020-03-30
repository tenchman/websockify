TARGETS=websockify
CFLAGS += -O0 -g -fPIE -fPIC -W -Wall -Wextra

all: $(TARGETS)

websockify: websockify.o websocket.o websocket_base64.o websocket_binary.o
	$(CC) $(LDFLAGS) $^ -lssl -lcrypto -lresolv -o $@

websocket.o: websocket.c websocket.h
websocket_base64.o: websocket_base64.c websocket.h
websocket_binary.o: websocket_binary.c websocket.h
websockify.o: websockify.c websocket.h

clean:
	rm -f websockify *.o


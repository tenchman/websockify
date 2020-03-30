#ifndef WEBSOCKET_H
#define WEBSOCKET_H 1

#include <netinet/in.h>
#include <openssl/ssl.h>

#define BUFSIZE 65536
#define DBUFSIZE (BUFSIZE * 3) / 4 - 20

#define SERVER_HANDSHAKE_HYBI "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\
Sec-WebSocket-Protocol: %s\r\n\
\r\n"

#define HYBI_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define HYBI10_ACCEPTHDRLEN 29
#define HANDSHAKELEN 4096

#define POLICY_RESPONSE "<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>\n"

#define WS_OPCODE_CONTINUATION  0x00
#define WS_OPCODE_TEXT          0x01
#define WS_OPCODE_BINARY        0x02
#define WS_OPCODE_CLOSE         0x08
#define WS_OPCODE_PING          0x09
#define WS_OPCODE_PONG          0x0A

typedef struct {
    char data[HANDSHAKELEN];
    char *path;
    char *host;
    char *origin;
    char *connection;
    char *protocols;
    char *key1;
    char *key2;
    char *key3;
} headers_t;

typedef struct ws_ctx_t ws_ctx_t;
struct ws_ctx_t {
    int        sockfd;
    SSL_CTX   *ssl_ctx;
    SSL       *ssl;
    int        version;
    int        base64;
    headers_t *headers;
    ssize_t (*recv) (ws_ctx_t *, void *, size_t);
    ssize_t (*send) (ws_ctx_t *, const void *, size_t);
    int (*encode)(uint8_t const *in, size_t inlen, uint8_t *out, size_t outlen, unsigned int opcode);
    int (*decode)(uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, unsigned int *opcode, unsigned int *left);
    uint8_t *cin_buf;
    uint8_t *cout_buf;
    uint8_t *tin_buf;
    uint8_t *tout_buf;
};

typedef struct {
    int verbose;
    char listen_host[256];
    int listen_port;
    void (*handler)(ws_ctx_t*);
    int handler_id;
    char *cert;
    char *key;
    char *hostmapfile;
    int ssl_only;
    int daemon;
    int run_once;
} settings_t;


ssize_t ws_recv(ws_ctx_t *ctx, void *buf, size_t len);
ssize_t ws_send(ws_ctx_t *ctx, const void *buf, size_t len);

int encode_base64(uint8_t const *src, size_t srclength,
                uint8_t *target, size_t targsize, unsigned int opcode);
int decode_base64(uint8_t *src, size_t srclength,
                uint8_t *target, size_t targsize,
                unsigned int *opcode, unsigned int *left);
int encode_binary(uint8_t const *src, size_t srclength,
                uint8_t *target, size_t targsize, unsigned int opcode);
int decode_binary(uint8_t *src, size_t srclength,
                uint8_t *target, size_t targsize,
                unsigned int *opcode, unsigned int *left);


void traffic(char *token);
int resolve_host(struct sockaddr_in6 *addr, const char *hostname, unsigned short port);
void start_server();

#define gen_handler_msg(stream, ...) \
    if (! settings.daemon) { \
        fprintf(stream, "  %d: ", settings.handler_id); \
        fprintf(stream, __VA_ARGS__); \
    }

#define handler_msg(...) gen_handler_msg(stdout, __VA_ARGS__);
#define handler_emsg(...) gen_handler_msg(stderr, __VA_ARGS__);

#endif

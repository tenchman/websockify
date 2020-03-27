/*
 * WebSocket lib with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h> /* umask */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h> // daemonizing
#include <fcntl.h>  // daemonizing
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>      /* base64 encode/decode */
#include <openssl/sha.h> /* sha1 hash */
#include "websocket.h"

/*
 * Global state
 *
 *   Warning: not thread safe
 */
int ssl_initialized = 0;
int pipe_error = 0;
settings_t settings;


void traffic(char * token) {
    if ((settings.verbose) && (! settings.daemon)) {
        fprintf(stdout, "%s", token);
        fflush(stdout);
    }
}

void error(char *msg)
{
    perror(msg);
}

void fatal(char *msg)
{
    perror(msg);
    exit(1);
}

/* resolve host with also IP address parsing */
int resolve_host(struct sockaddr_in6 *addr, const char *hostname, unsigned short port)
{
    struct addrinfo *ai, *cur;
    struct addrinfo hints;
    char service[6];
    memset(&hints, 0, sizeof(hints));

    snprintf(service, 6, "%hu", port);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(hostname, service, &hints, &ai))
        return -1;

    for (cur = ai; cur; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET || cur->ai_family == AF_INET6) {
            memcpy(addr, cur->ai_addr, sizeof(struct sockaddr));
            freeaddrinfo(ai);
            return 0;
        }
    }
    freeaddrinfo(ai);
    return -1;
}

/*
 * SSL Wrapper Code
 */

static ssize_t std_recv(ws_ctx_t *ctx, void *buf, size_t len)
{
  return recv(ctx->sockfd, buf, len, 0);
}

static ssize_t ssl_recv(ws_ctx_t *ctx, void *buf, size_t len)
{
  return SSL_read(ctx->ssl, buf, len);
}

ssize_t ws_recv(ws_ctx_t *ctx, void *buf, size_t len)
{
  return ctx->recv(ctx, buf, len);
}

static ssize_t std_send(ws_ctx_t *ctx, const void *buf, size_t len)
{
  return send(ctx->sockfd, buf, len, 0);
}

static ssize_t ssl_send(ws_ctx_t *ctx, const void *buf, size_t len)
{
  return SSL_write(ctx->ssl, buf, len);
}

ssize_t ws_send(ws_ctx_t *ctx, const void *buf, size_t len)
{
  return ctx->send(ctx, buf, len);
}

#define BUFFERSIZE sizeof(ws_ctx_t) + sizeof(headers_t) + BUFSIZE * 4

static ws_ctx_t *alloc_ws_ctx(void)
{
    ws_ctx_t *ctx;
    void *ptr;

    if (NULL == (ptr = calloc(1, BUFFERSIZE))) {
      fatal("malloc()");
    }

    ctx = ptr; ptr += sizeof(ws_ctx_t);
    ctx->headers = ptr; ptr += sizeof(headers_t);

    ctx->cin_buf  = ptr;
    ctx->cout_buf = ctx->cin_buf  + BUFSIZE;
    ctx->tin_buf  = ctx->cout_buf + BUFSIZE;
    ctx->tout_buf = ctx->tin_buf  + BUFSIZE;

    ctx->ssl = NULL;
    ctx->ssl_ctx = NULL;
    return ctx;
}

static void free_ws_ctx(ws_ctx_t *ctx)
{
    free(ctx);
}

static void ws_socket(ws_ctx_t *ctx, int socket) {
    ctx->sockfd = socket;
    ctx->recv = std_recv;
    ctx->send = std_send;
}

ws_ctx_t *ws_socket_ssl(ws_ctx_t *ctx, int socket, char * certfile, char * keyfile) {
    int ret;
    char msg[1024];
    char * use_keyfile;
    ws_socket(ctx, socket);

    if (keyfile && (keyfile[0] != '\0')) {
        // Separate key file
        use_keyfile = keyfile;
    } else {
        // Combined key and cert file
        use_keyfile = certfile;
    }

    // Initialize the library
    if (! ssl_initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_initialized = 1;
    }

    ctx->ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    if (ctx->ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        fatal("Failed to configure SSL context");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, use_keyfile,
                                    SSL_FILETYPE_PEM) <= 0) {
        sprintf(msg, "Unable to load private key file %s\n", use_keyfile);
        fatal(msg);
    }

    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, certfile,
                                     SSL_FILETYPE_PEM) <= 0) {
        sprintf(msg, "Unable to load certificate file %s\n", certfile);
        fatal(msg);
    }

//    if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, "DEFAULT") != 1) {
//        sprintf(msg, "Unable to set cipher\n");
//        fatal(msg);
//    }

    // Associate socket and ssl object
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ctx->ssl, socket);

    ret = SSL_accept(ctx->ssl);
    if (ret < 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    ctx->recv = ssl_recv;
    ctx->send = ssl_send;

    return ctx;
}

void ws_socket_free(ws_ctx_t *ctx) {
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    if (ctx->sockfd) {
        shutdown(ctx->sockfd, SHUT_RDWR);
        close(ctx->sockfd);
        ctx->sockfd = 0;
    }
}

/* ------------------------------------------------------- */
int encode_hybi(unsigned char const *src, size_t srclength,
                unsigned char *target, size_t targsize, unsigned int opcode)
{
    unsigned long long b64_sz, payload_offset = 2;
    int len = 0;

    if ((int)srclength <= 0)
    {
        return 0;
    }

    b64_sz = ((srclength - 1) / 3) * 4 + 4;

    target[0] = (char)((opcode & 0x0F) | 0x80);

    if (b64_sz <= 125) {
        target[1] = (char) b64_sz;
        payload_offset = 2;
    } else if ((b64_sz > 125) && (b64_sz < 65536)) {
        target[1] = (char) 126;
        *(u_short*)&(target[2]) = htons(b64_sz);
        payload_offset = 4;
    } else {
        handler_emsg("Sending frames larger than 65535 bytes not supported\n");
        return -1;
        //target[1] = (char) 127;
        //*(u_long*)&(target[2]) = htonl(b64_sz);
        //payload_offset = 10;
    }

    len = b64_ntop(src, srclength, (char *)target+payload_offset, targsize-payload_offset);

    if (len < 0) {
        return len;
    }

    return len + payload_offset;
}

int decode_hybi(unsigned char *src, size_t srclength,
                u_char *target, size_t targsize,
                unsigned int *opcode, unsigned int *left)
{
    unsigned char *frame, *mask, *payload, save_char;
    char cntstr[4];
    int masked = 0;
    int len, framecount = 0;
    size_t remaining = 0;
    unsigned int i = 0, target_offset = 0, hdr_length = 0, payload_length = 0;

    *left = srclength;
    frame = src;

    //printf("Deocde new frame\n");
    while (1) {
        // Need at least two bytes of the header
        // Find beginning of next frame. First time hdr_length, masked and
        // payload_length are zero
        frame += hdr_length + 4*masked + payload_length;
        //printf("frame[0..3]: 0x%x 0x%x 0x%x 0x%x (tot: %d)\n",
        //       (unsigned char) frame[0],
        //       (unsigned char) frame[1],
        //       (unsigned char) frame[2],
        //       (unsigned char) frame[3], srclength);

        if (frame > src + srclength) {
            //printf("Truncated frame from client, need %d more bytes\n", frame - (src + srclength) );
            break;
        }
        remaining = (src + srclength) - frame;
        if (remaining < 2) {
            //printf("Truncated frame header from client\n");
            break;
        }
        framecount ++;

        *opcode = frame[0] & 0x0f;
        masked = (frame[1] & 0x80) >> 7;

        if (*opcode == WS_OPCODE_CLOSE) {
            // client sent orderly close frame
            break;
        }

        payload_length = frame[1] & 0x7f;
        if (payload_length < 126) {
            hdr_length = 2;
            //frame += 2 * sizeof(char);
        } else if (payload_length == 126) {
            payload_length = (frame[2] << 8) + frame[3];
            hdr_length = 4;
        } else {
            handler_emsg("Receiving frames larger than 65535 bytes not supported\n");
            return -1;
        }
        if ((hdr_length + 4*masked + payload_length) > remaining) {
            continue;
        }
        //printf("    payload_length: %u, raw remaining: %u\n", payload_length, remaining);
        payload = frame + hdr_length + 4*masked;

        if (*opcode != WS_OPCODE_TEXT && *opcode != WS_OPCODE_BINARY) {
            handler_msg("Ignoring non-data frame, opcode 0x%x\n", *opcode);
            continue;
        }

        if (payload_length == 0) {
            handler_msg("Ignoring empty frame\n");
            continue;
        }

        if ((payload_length > 0) && (!masked)) {
            handler_emsg("Received unmasked payload from client\n");
            return -1;
        }

        // Terminate with a null for base64 decode
        save_char = payload[payload_length];
        payload[payload_length] = '\0';

        // unmask the data
        mask = payload - 4;
        for (i = 0; i < payload_length; i++) {
            payload[i] ^= mask[i%4];
        }

        // base64 decode the data
        len = b64_pton((const char*)payload, target+target_offset, targsize);

        // Restore the first character of the next frame
        payload[payload_length] = save_char;
        if (len < 0) {
            handler_emsg("Base64 decode error code %d", len);
            return len;
        }
        target_offset += len;

        //printf("    len %d, raw %s\n", len, frame);
    }

    if (framecount > 1) {
        snprintf(cntstr, 3, "%d", framecount);
        traffic(cntstr);
    }

    *left = remaining;
    return target_offset;
}

static inline int startswith(char *haystack, char *needle)
{
    int n = strlen(needle);
    return 0 == bcmp(haystack, needle, n) ? n : 0;
}

static int parse_handshake(ws_ctx_t *ws_ctx, char *handshake)
{
    char *eol, *start, *end;
    headers_t *headers = ws_ctx->headers;
    int n, ret = 0;

    if ((n = strlen(handshake)) < 92) {
        /* */
    } else if (n > HANDSHAKELEN - 2) {
        /* impossible, just in case ... */
    } else if (bcmp(handshake, "GET ", 4) != 0) {
        /* */
    } else {

        memcpy(headers->data, handshake, n + 1); /* copy with trailing '\0' */
        eol = headers->data;

        while (1) {
            start = eol;

            if (NULL == (eol = strstr(start, "\r\n"))) {
                break;
            } else {
                *eol = '\0';
                eol += 2;       /* advance over '\r\n' */
            }

            if (0 == bcmp(start, "\r\n", 2)) {
                break;
            } else if ((n = startswith(start, "GET "))) {
                headers->path = start + n;
                if (NULL == (end = strstr(start, " HTTP/1.1")))
                    return 0;
                *end = '\0';
            } else if ((n = startswith(start, "Host: "))) {
                headers->host = start + n;
            } else if ((n = startswith(start, "Origin: "))) {
                headers->origin = start + n;
            } else if ((n = startswith(start, "Sec-WebSocket-Origin: "))) {
                headers->origin = start + n;
            } else if ((n = startswith(start, "Sec-WebSocket-Version: "))) {
                ws_ctx->version = strtol(start + n, NULL, 10);
            } else if ((n = startswith(start, "Sec-WebSocket-Key: "))) {
                headers->key1 = start + n;
            } else if ((n = startswith(start, "Sec-WebSocket-Protocol: "))) {
                headers->protocols = start + n;
            } else if ((n = startswith(start, "Connection: "))) {
                headers->connection = start + n;
            }
        }

        /* check plausibility */
        if (NULL == headers->path) {
            handler_emsg("%s: missing path\n", __func__);
        } else if (NULL == headers->host) {
            handler_emsg("%s: missing host\n", __func__);
        } else if (NULL == headers->key1) {
            handler_emsg("%s: missing key1\n", __func__);
        } else if (NULL == headers->origin) {
            handler_emsg("%s: missing origin\n", __func__);
        } else {
            ret = 1;
        }
    }
    return ret;
}

static void gen_sha1(headers_t *headers, char *target) {
    SHA_CTX c;
    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1_Init(&c);
    SHA1_Update(&c, headers->key1, strlen(headers->key1));
    SHA1_Update(&c, HYBI_GUID, 36);
    SHA1_Final(hash, &c);

    b64_ntop(hash, sizeof hash, target, HYBI10_ACCEPTHDRLEN);
}


static ws_ctx_t *do_handshake(int sock) {
    char handshake[HANDSHAKELEN], response[4096];
    char sha1[HYBI10_ACCEPTHDRLEN + 1] = {};
    headers_t *headers;
    int len, i, offset;
    ws_ctx_t * ws_ctx;

    // Peek, but don't read the data
    if (-1 == (len = recv(sock, handshake, 1024, MSG_PEEK))) {
        handler_msg("Error reading initial handshake data: %m\n");
        return NULL;
    }
    handshake[len] = 0;
    if (len == 0) {
        handler_msg("ignoring empty handshake\n");
        return NULL;
    } else if (bcmp(handshake, "<policy-file-request/>", 22) == 0) {
        if (-1 == (len = recv(sock, handshake, 1024, 0))) {
            handler_msg("Error reading initial handshake data: %m\n");
        } else {
            handshake[len] = 0;
            handler_msg("sending flash policy response\n");
            if (-1 == send(sock, POLICY_RESPONSE, sizeof(POLICY_RESPONSE), 0))
                handler_msg("Error sending flash policy response: %m\n");
        }
        return NULL;
    } else if ((bcmp(handshake, "\x16", 1) == 0) ||
               (bcmp(handshake, "\x80", 1) == 0)) {
        // SSL
        if (!settings.cert) {
            handler_msg("SSL connection but no cert specified\n");
            return NULL;
        } else if (access(settings.cert, R_OK) != 0) {
            handler_msg("SSL connection but '%s' not found\n",
                        settings.cert);
            return NULL;
        }
        if (NULL == (ws_ctx = alloc_ws_ctx())) {
            handler_msg("Memory allocation failed\n");
            return NULL;
        }
        ws_socket_ssl(ws_ctx, sock, settings.cert, settings.key);
        handler_msg("using SSL socket\n");
    } else if (settings.ssl_only) {
        handler_msg("non-SSL connection disallowed\n");
        return NULL;
    } else {
        if (NULL == (ws_ctx = alloc_ws_ctx())) {
            handler_msg("Memory allocation failed\n");
            return NULL;
        }
        ws_socket(ws_ctx, sock);
        handler_msg("using plain (not SSL) socket\n");
    }
    offset = 0;

    for (i = 0; i < 10; i++) {
        /* (offset + 1): reserve one byte for the trailing '\0' */
        if (0 > (len = ws_recv(ws_ctx, handshake + offset, sizeof(handshake) - (offset + 1)))) {
            handler_emsg("Read error during handshake: %m\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        } else if (0 == len) {
            handler_emsg("Client closed during handshake\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        }
        offset += len;
        handshake[offset] = 0;

        if (strstr(handshake, "\r\n\r\n")) {
            break;
        } else if (sizeof(handshake) <= (size_t)(offset + 1)) {
            handler_emsg("Oversized handshake\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        } else if (9 == i) {
            handler_emsg("Incomplete handshake\n");
            free_ws_ctx(ws_ctx);
            return NULL;
        }
        usleep(10);
    }

    //handler_msg("handshake: %s\n", handshake);
    if (!parse_handshake(ws_ctx, handshake)) {
        handler_emsg("Invalid WS request\n");
        free_ws_ctx(ws_ctx);
        return NULL;
    }

    headers = ws_ctx->headers;
    handler_msg("using protocol HyBi/IETF 6455 %d\n", ws_ctx->version);
    gen_sha1(headers, sha1);
    len = snprintf(response, sizeof(response), SERVER_HANDSHAKE_HYBI, sha1, "base64");

    //handler_msg("response: %s\n", response);
    ws_send(ws_ctx, response, len);

    return ws_ctx;
}

void signal_handler(int sig) {
    switch (sig) {
        case SIGHUP: break; // ignore for now
        case SIGPIPE: pipe_error = 1; break; // handle inline
        case SIGTERM: exit(0); break;
    }
}

void daemonize(int keepfd) {
    int pid, i;

    umask(0);
    chdir("/");
    setgid(getgid());
    setuid(getuid());

    /* Double fork to daemonize */
    pid = fork();
    if (pid<0) { fatal("fork error"); }
    if (pid>0) { exit(0); }  // parent exits
    setsid();                // Obtain new process group
    pid = fork();
    if (pid<0) { fatal("fork error"); }
    if (pid>0) { exit(0); }  // parent exits

    /* Signal handling */
    signal(SIGHUP, signal_handler);   // catch HUP
    signal(SIGTERM, signal_handler);  // catch kill

    /* Close open files */
    for (i=getdtablesize(); i>=0; --i) {
        if (i != keepfd) {
            close(i);
        } else if (settings.verbose) {
            printf("keeping fd %d\n", keepfd);
        }
    }
    if (-1 == (i = open("/dev/null", O_RDWR))) {  // Redirect stdin
        fatal("error opening /dev/null");
    } else {
        dup(i);                       // Redirect stdout
        dup(i);                       // Redirect stderr
    }
}


void start_server() {
    int lsock, csock, pid, sopt = 1;
    socklen_t clilen;
    struct sockaddr_in6 serv_addr, cli_addr;
    char cliaddr[INET6_ADDRSTRLEN];
    ws_ctx_t *ws_ctx;


    /* Initialize buffers */
    bzero((char *) &serv_addr, sizeof(serv_addr));

    /* Resolve listen address */
    if (resolve_host(&serv_addr, settings.listen_host, settings.listen_port) < -1) {
        fatal("Could not resolve listen address");
    }

    lsock = socket(serv_addr.sin6_family, SOCK_STREAM, 0);
    if (lsock < 0) {
        fatal("ERROR creating listener socket");
    }

    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&sopt, sizeof(sopt));
    if (bind(lsock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        fatal("ERROR on binding listener socket");
    }
    listen(lsock,100);

    signal(SIGPIPE, signal_handler);  // catch pipe

    if (settings.daemon) {
        daemonize(lsock);
    }


    // Reep zombies
    signal(SIGCHLD, SIG_IGN);

    printf("Waiting for connections on [%s]:%d\n",
            settings.listen_host, settings.listen_port);

    while (1) {
        clilen = sizeof(cli_addr);
        pipe_error = 0;
        pid = 0;
        csock = accept(lsock, (struct sockaddr *)&cli_addr, &clilen);
        if (csock < 0) {
            error("ERROR on accept");
            continue;
        }
        if (cli_addr.sin6_family == AF_INET)
	  inet_ntop(cli_addr.sin6_family, &(((struct sockaddr_in *)&cli_addr)->sin_addr), cliaddr, sizeof(cliaddr));
	else
	  inet_ntop(cli_addr.sin6_family, &(((struct sockaddr_in6 *)&cli_addr)->sin6_addr), cliaddr, sizeof(cliaddr));

	handler_msg("got client connection from %s\n", cliaddr);

        if (!settings.run_once) {
            handler_msg("forking handler process\n");
            pid = fork();
        }

        if (pid == 0) {  // handler process
            ws_ctx = do_handshake(csock);
            if (settings.run_once) {
                if (ws_ctx == NULL) {
                    // Not a real WebSocket connection
                    close(csock);
                    continue;
                } else {
                    // Successful connection, stop listening for new
                    // connections
                    close(lsock);
                    lsock = -1;
                }
            } else {
              // close listening socket in child
              close(lsock);
              lsock = -1;
            }
            if (ws_ctx == NULL) {
                handler_msg("No connection after handshake\n");
                break;   // Child process exits
            }

            settings.handler(ws_ctx);
            if (pipe_error) {
                handler_emsg("Closing due to SIGPIPE\n");
            }
            break;   // Child or run-once process exits
        } else {         // parent process
            settings.handler_id += 1;
        }
        close(csock);
    }

    if (-1 != lsock)
        close(lsock);

    if (pid == 0) {
        if (ws_ctx) {
            ws_socket_free(ws_ctx);
            free_ws_ctx(ws_ctx);
        } else {
            shutdown(csock, SHUT_RDWR);
            close(csock);
        }
        handler_msg("handler exit\n");
    } else {
        handler_msg("websockify exit\n");
    }

}


#include "websocket.h"
#include <netinet/in.h>
#include <resolv.h> /* base64 encode/decode */
#include <string.h>

extern settings_t settings;

int encode_base64(uint8_t const *src, size_t srclength,
                  uint8_t *target, size_t targsize)
{
    unsigned long long b64_sz, payload_offset = 2;
    int len = 0;

    if ((int)srclength <= 0) {
        return 0;
    }

    b64_sz = ((srclength - 1) / 3) * 4 + 4;

    target[0] = (char)((WS_OPCODE_TEXT & 0x0F) | 0x80);

    if (b64_sz <= 125) {
        target[1] = (char)b64_sz;
        payload_offset = 2;
    } else if ((b64_sz > 125) && (b64_sz < 65536)) {
        target[1] = (char)126;
        *(u_short *)&(target[2]) = htons(b64_sz);
        payload_offset = 4;
    } else {
        handler_emsg("Sending frames larger than 65535 bytes not supported\n");
        return -1;
        //target[1] = (char) 127;
        //*(u_long*)&(target[2]) = htonl(b64_sz);
        //payload_offset = 10;
    }

    len = b64_ntop(src, srclength, (char *)target + payload_offset, targsize - payload_offset);

    if (len < 0) {
        return len;
    }

    return len + payload_offset;
}

int decode_base64(uint8_t *src, size_t srclength,
                  uint8_t *target, size_t targsize,
                  unsigned int *opcode, unsigned int *left)
{
    unsigned char *frame, *mask, *payload, save_char;
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
        frame += hdr_length + 4 * masked + payload_length;
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
        framecount++;

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
        if ((hdr_length + 4 * masked + payload_length) > remaining) {
            continue;
        }
        //printf("    payload_length: %u, raw remaining: %u\n", payload_length, remaining);
        payload = frame + hdr_length + 4 * masked;

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
            payload[i] ^= mask[i % 4];
        }

        // base64 decode the data
        len = b64_pton((const char *)payload, target + target_offset, targsize);

        // Restore the first character of the next frame
        payload[payload_length] = save_char;
        if (len < 0) {
            handler_emsg("Base64 decode error code %d", len);
            return len;
        }
        target_offset += len;

        //printf("    len %d, raw %s\n", len, frame);
    }

    *left = remaining;
    return target_offset;
}

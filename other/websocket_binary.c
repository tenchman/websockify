#include "websocket.h"
#include <netinet/in.h>
#include <string.h>
#include <syslog.h>

extern settings_t settings;

int encode_binary(uint8_t const *src, size_t srclength,
                  uint8_t *target, size_t targsize)
{
    int payload_offset = 2;

    if ((int)srclength <= 0) {
        return 0;
    }

    target[0] = (uint8_t)(WS_OPCODE_BINARY | 0x80);

    if (srclength <= 125) {
        target[1] = (uint8_t)srclength;
        payload_offset = 2;
    } else if ((srclength > 125) && (srclength < 65536)) {
        target[1] = (uint8_t)126;
        *(uint16_t *)&(target[2]) = htons(srclength);
        payload_offset = 4;
    } else {
        /* TODO: support bigger frames */
        handler_emsg("Sending frames larger than 65535 bytes not supported\n");
        return -1;
    }

    if (targsize < srclength + payload_offset)
        return -1;

    memcpy(target + payload_offset, src, srclength);
    return srclength + payload_offset;
}

int decode_binary(uint8_t *src, size_t srclength,
                  uint8_t *target, size_t targsize,
                  unsigned int *opcode, unsigned int *left)
{
    unsigned char *frame, *mask, *payload;
    char cntstr[4];
    int masked = 0;
    int framecount = 0;
    size_t remaining = 0;
    unsigned int i = 0, target_offset = 0, hdr_length = 0, payload_length = 0;

    *left = srclength;
    frame = src;

    //printf("Deocde new frame\n");
    while (1) {
        /* Need at least two bytes of the header
           Find beginning of next frame. First time hdr_length, masked and
           payload_length are zero
        **/
        frame += hdr_length + 4 * masked + payload_length;
        if (frame > src + srclength) {
            //printf("Truncated frame from client, need %d more bytes\n", frame - (src + srclength) );
            break;
        }
        remaining = (src + srclength) - frame;
        if (remaining < 2) {
            syslog(LOG_DEBUG, "%s: truncated frame header from client", __func__);
            break;
        }
        framecount++;

        *opcode = frame[0] & 0x0f;
        masked = (frame[1] & 0x80) >> 7;

        if (*opcode == WS_OPCODE_CLOSE) {
            /* client sent orderly close frame */
            break;
        }

        payload_length = frame[1] & 0x7f;
        if (payload_length < 126) {
            hdr_length = 2;
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

        if (targsize < target_offset + payload_length) {
            handler_emsg("Target buffer to small\n");
            return -1;
        }

        /* unmask the data
         * TODO: here is room for optimizations
        **/
        mask = payload - 4;
        for (i = 0; i < payload_length; i++) {
            payload[i] ^= mask[i % 4];
        }

        memcpy(target + target_offset, payload, payload_length);
        target_offset += payload_length;
    }

    if (framecount > 1) {
        snprintf(cntstr, 3, "%d", framecount);
        traffic(cntstr);
    }

    *left = remaining;
    return target_offset;
}

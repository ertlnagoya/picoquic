/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
* Packet logging.
*/

#include "userq_settings.h"

#ifdef USE_LWIP
#include "lwip/sockets.h"
#include <t_syslog.h>
#endif
#include "fnv1a.h"
#include "picoquic_internal.h"
#include "tls_api.h"

#ifdef DISABLE_DEBUG_PRINTF
void picoquic_log_decrypted_segment(int log_cnxid, picoquic_cnx_t* cnx, int receiving, 
        picoquic_packet_header * ph, uint8_t* bytes, size_t length, int ret)
{
    return;
}

void picoquic_log_outgoing_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx, uint8_t * bytes,
    uint64_t sequence_number, uint32_t length, uint8_t* send_buffer, uint32_t send_length)
{
    return;
}

void picoquic_log_packet_address(uint64_t log_cnxid64, picoquic_cnx_t* cnx,
    struct sockaddr* addr_peer, int receiving, size_t length, uint64_t current_time)
{
    return;
}

void picoquic_log_prefix_initial_cid64(uint64_t log_cnxid64)
{
    return;
}

/* Handling of cc_log */
void picoquic_open_cc_dump(picoquic_cnx_t * cnx)
{
    return;
}

void picoquic_close_cc_dump(picoquic_cnx_t * cnx)
{
    return;
}
void picoquic_cc_dump(picoquic_cnx_t * cnx, uint64_t current_time)
{
    return;
}

void picoquic_log_error_packet(uint8_t* bytes, size_t bytes_max, int ret)
{
    syslog(LOG_ERROR, "Packet length %d caused error: %d\n", (int)bytes_max, ret);
}

void picoquic_log_processing(picoquic_cnx_t* cnx, size_t length, int ret)
{
    return;
}

void picoquic_log_transport_extension(picoquic_cnx_t* cnx, int log_cnxid)
{
    return;
}

void picoquic_log_picotls_ticket(picoquic_connection_id_t cnx_id, uint8_t* ticket, uint16_t ticket_length)
{
    return;
}

#else /* DISABLE_DEBUG_PRINTF */

void picoquic_log_bytes(uint8_t* bytes, size_t bytes_max)
{
    for (size_t i = 0; i < bytes_max;) {
        DBG_PRINTF("%04x:  ", (int)i);

        for (int j = 0; j < 16 && i < bytes_max; j++, i++) {
            DBG_PRINTF("%02x ", bytes[i]);
        }
        DBG_PRINTF("");
    }
}

void picoquic_log_error_packet(uint8_t* bytes, size_t bytes_max, int ret)
{
    syslog(LOG_NOTICE, "Packet length %d caused error: %d\n", (int)bytes_max, ret);

    picoquic_log_bytes(bytes, bytes_max);

    DBG_PRINTF("\n");
}

void picoquic_log_time(picoquic_cnx_t* cnx, uint64_t current_time,
    const char* label1, const char* label2)
{
    uint64_t delta_t = (cnx == NULL) ? current_time : current_time - cnx->start_time;
    uint64_t time_sec = delta_t / 1000000;
    uint32_t time_usec = (uint32_t)(delta_t % 1000000);

    DBG_PRINTF("%s%lu%lu.%06d%s", label1, (uint32_t)(time_sec >> 32),
         (uint32_t)time_sec, time_usec, label2);
}

const char * picoquic_log_fin_or_event_name(picoquic_call_back_event_t ev)
{
    char const * text = "unknown";
    switch (ev) {
    case picoquic_callback_stream_data:
        text = "stream data";
        break;
    case picoquic_callback_stream_fin:
        text = "stream fin";
        break;
    case picoquic_callback_stream_reset:
        text = "stream reset";
        break;
    case picoquic_callback_stop_sending:
        text = "stop sending";
        break;
    case picoquic_callback_close:
        text = "connection close";
        break;
    case picoquic_callback_application_close:
        text = "application close";
        break;
    case picoquic_callback_stream_gap:
        text = "stream gap";
        break;
    case picoquic_callback_prepare_to_send:
        text = "ready to send";
        break;
    case picoquic_callback_almost_ready:
        text = "almost ready";
        break;
    case picoquic_callback_ready:
        text = "ready";
        break;
    default:
        break;
    }

    return text;
}

void picoquic_log_prefix_initial_cid64(uint64_t log_cnxid64)
{
    if (log_cnxid64 != 0) {
        DBG_PRINTF("%08lx%08lx: ", (uint32_t)(log_cnxid64 >> 32), (uint32_t)log_cnxid64);
    }
}

void picoquic_log_packet_address(uint64_t log_cnxid64, picoquic_cnx_t* cnx,
    struct sockaddr* addr_peer, int receiving, size_t length, uint64_t current_time)
{
    uint64_t delta_t = 0;
    uint64_t time_sec = 0;
    uint32_t time_usec = 0;

    DBG_FLUSH();
    picoquic_log_prefix_initial_cid64(log_cnxid64);

    DBG_PRINTF((receiving) ? "Receiving %d bytes from " : "Sending %d bytes to ", (int)length);

    if (addr_peer->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)addr_peer;
        uint8_t* addr = (uint8_t*)&s4->sin_addr;

        DBG_PRINTF("%d.%d.%d.%d:%d",
            addr[0], addr[1], addr[2], addr[3],
            ntohs(s4->sin_port));
#if (AF_INET6 != 0)
    } else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)addr_peer;
        uint8_t* addr = (uint8_t*)&s6->sin6_addr;

        for (int i = 0; i < 8; i++) {
            if (i != 0) {
                DBG_PRINTF(":");
            }

            if (addr[2 * i] != 0) {
                DBG_PRINTF("%x%02x", addr[2 * i], addr[(2 * i) + 1]);
            } else {
                DBG_PRINTF("%x", addr[(2 * i) + 1]);
            }
        }
#endif
    }

    if (cnx != NULL) {
        delta_t = current_time - cnx->start_time;
        time_sec = delta_t / 1000000;
        time_usec = (uint32_t)(delta_t % 1000000);
    }

    DBG_PRINTF(" at T=%d.%06d (%d)\n", (uint32_t)time_sec, time_usec, (uint32_t)current_time);
    DBG_FLUSH();
}

char const* picoquic_log_state_name(picoquic_state_enum state)
{
    char const* state_name = "unknown";

    switch (state) {
    case picoquic_state_client_init: 
        state_name = "client_init"; 
        break;
    case picoquic_state_client_init_sent: 
        state_name = "client_init_sent"; 
        break;
    case picoquic_state_client_renegotiate: 
        state_name = "client_renegotiate"; 
        break;
    case picoquic_state_client_retry_received: 
        state_name = "client_retry_received"; 
        break;
    case picoquic_state_client_init_resent: 
        state_name = "client_init_resent"; 
        break;
    case picoquic_state_server_init: 
        state_name = "server_init"; 
        break;
    case picoquic_state_server_handshake:
        state_name = "server_handshake";
        break;
    case picoquic_state_client_handshake_start: 
        state_name = "client_handshake_start"; 
        break;
    case picoquic_state_client_handshake_progress: 
        state_name = "client_handshake_progress"; 
        break;
    case picoquic_state_client_almost_ready: 
        state_name = "client_almost_ready";
        break;
    case picoquic_state_handshake_failure:
        state_name = "handshake_failure";
        break;
    case picoquic_state_server_almost_ready:
        state_name = "server_almost_ready";
        break;
    case picoquic_state_server_false_start:
        state_name = "server_false_start";
        break;
    case picoquic_state_client_ready_start:
        state_name = "client_ready_start";
        break;
    case picoquic_state_ready:
        state_name = "ready";
        break;
    case picoquic_state_disconnecting:
        state_name = "disconnecting";
        break;
    case picoquic_state_closing_received:
        state_name = "closing_received";
        break;
    case picoquic_state_closing:
        state_name = "closing"; 
        break;
    case picoquic_state_draining:
        state_name = "draining"; 
        break;
    case picoquic_state_disconnected:
        state_name = "disconnected"; 
        break;
    default:
        break;
    }
    return state_name;
}

char const* picoquic_log_ptype_name(picoquic_packet_type_enum ptype)
{
    char const* ptype_name = "unknown";

    switch (ptype) {
    case picoquic_packet_error:
        ptype_name = "error";
        break;
    case picoquic_packet_version_negotiation:
        ptype_name = "version negotiation";
        break;
    case picoquic_packet_initial:
        ptype_name = "initial";
        break;
    case picoquic_packet_retry:
        ptype_name = "retry";
        break;
    case picoquic_packet_handshake:
        ptype_name = "handshake";
        break;
    case picoquic_packet_0rtt_protected:
        ptype_name = "0rtt protected";
        break;
    case picoquic_packet_1rtt_protected:
        ptype_name = "1rtt protected";
        break;
    default:
        break;
    }

    return ptype_name;
}

char const* picoquic_log_frame_names(uint8_t frame_type)
{
    char const * frame_name = "unknown";
    
    switch ((picoquic_frame_type_enum_t)frame_type) {
    case picoquic_frame_type_padding:
        frame_name = "padding";
        break;
    case picoquic_frame_type_reset_stream:
        frame_name = "reset_stream";
        break;
    case picoquic_frame_type_connection_close:
        frame_name = "connection_close";
        break;
    case picoquic_frame_type_application_close:
        frame_name = "application_close";
        break;
    case picoquic_frame_type_max_data:
        frame_name = "max_data";
        break;
    case picoquic_frame_type_max_stream_data:
        frame_name = "max_stream_data";
        break;
    case picoquic_frame_type_max_streams_bidir:
        frame_name = "max_streams_bidir";
        break;
    case picoquic_frame_type_max_streams_unidir:
        frame_name = "max_streams_unidir";
        break;
    case picoquic_frame_type_ping:
        frame_name = "ping";
        break;
    case picoquic_frame_type_data_blocked:
        frame_name = "data_blocked";
        break;
    case picoquic_frame_type_stream_data_blocked:
        frame_name = "stream_data_blocked";
        break;
    case picoquic_frame_type_streams_blocked_bidir:
        frame_name = "streams_blocked_bidir";
        break;
    case picoquic_frame_type_streams_blocked_unidir:
        frame_name = "streams_blocked_unidir";
        break;
    case picoquic_frame_type_new_connection_id:
        frame_name = "new_connection_id";
        break;
    case picoquic_frame_type_stop_sending:
        frame_name = "stop_sending";
        break;
    case picoquic_frame_type_ack:
        frame_name = "ack";
        break;
    case picoquic_frame_type_path_challenge:
        frame_name = "path_challenge";
        break;
    case picoquic_frame_type_path_response:
        frame_name = "path_response";
        break;
    case picoquic_frame_type_crypto_hs:
        frame_name = "crypto_hs";
        break;
    case picoquic_frame_type_new_token:
        frame_name = "new_token";
        break;
    case picoquic_frame_type_ack_ecn:
        frame_name = "ack_ecn";
        break;
    case picoquic_frame_type_retire_connection_id:
        frame_name = "retire_connection_id";
        break;
    default:
        if (PICOQUIC_IN_RANGE(frame_type, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            frame_name = "stream";
        }
        break;
    }

    return frame_name;
}

void picoquic_log_connection_id(picoquic_connection_id_t * cid)
{
    DBG_PRINTF("<");
    for (uint8_t i = 0; i < cid->id_len; i++) {
        DBG_PRINTF("%02x", cid->id[i]);
    }
    DBG_PRINTF(">");
}

void picoquic_log_packet_header(uint64_t log_cnxid64, picoquic_packet_header* ph, int receiving)
{
    DBG_FLUSH();
    //DBG_PRINTF("\n");
    picoquic_log_prefix_initial_cid64(log_cnxid64);

    DBG_PRINTF("%s packet type: %d (%s), ", (receiving != 0)?"Receiving":"Sending",
        ph->ptype, picoquic_log_ptype_name(ph->ptype));

    DBG_PRINTF("S%d,", ph->spin);

    switch (ph->ptype) {
    case picoquic_packet_1rtt_protected:
        /* Short packets. Log dest CID and Seq number. */
        DBG_PRINTF("\n");
        picoquic_log_prefix_initial_cid64(log_cnxid64);
        DBG_PRINTF("    ");
        picoquic_log_connection_id(&ph->dest_cnx_id);
        DBG_PRINTF(", Seq: %d (%lu%lu), Phi: %d,\n", ph->pn,
         (uint32_t)(ph->pn64 >> 32), (uint32_t)ph->pn64, ph->key_phase);
        DBG_FLUSH();
        break;
    case picoquic_packet_version_negotiation:
        /* V nego. log both CID */
        DBG_PRINTF("    ");
        picoquic_log_connection_id(&ph->dest_cnx_id);
        DBG_PRINTF(", ");
        picoquic_log_connection_id(&ph->srce_cnx_id);
        DBG_PRINTF("\n");
        DBG_FLUSH();
        break;
    default:
        /* Long packets. Log Vnum, both CID, Seq num, Payload length */
        DBG_PRINTF(" Version %x,\n", ph->vn);
        DBG_FLUSH();
        picoquic_log_prefix_initial_cid64(log_cnxid64);
        DBG_PRINTF("    ");
        picoquic_log_connection_id(&ph->dest_cnx_id);
        DBG_PRINTF(", ");
        picoquic_log_connection_id(&ph->srce_cnx_id);
        DBG_PRINTF(", Seq: %x, pl: %d\n", ph->pn, ph->pl_val);
        DBG_FLUSH();
        if (ph->ptype == picoquic_packet_initial) {
            picoquic_log_prefix_initial_cid64(log_cnxid64);
            DBG_PRINTF("    Token length: %d", ph->token_length);
            if (ph->token_length > 0) {
                uint32_t printed_length = (ph->token_length > 16) ? 16 : ph->token_length;
                DBG_PRINTF(", Token: ");
                for (uint8_t i = 0; i < printed_length; i++) {
                    DBG_PRINTF("%02x", ph->token_bytes[i]);
                }
                if (printed_length < ph->token_length) {
                    DBG_PRINTF("...");
                }
            }
            DBG_PRINTF("\n");
        }
        break;
    }
}

void picoquic_log_negotiation_packet(uint64_t log_cnxid64,
    uint8_t* bytes, size_t length, picoquic_packet_header* ph)
{
    size_t byte_index = ph->offset;
    uint32_t vn = 0;

    picoquic_log_prefix_initial_cid64(log_cnxid64);

    DBG_PRINTF("    versions: ");

    while (byte_index + 4 <= length) {
        vn = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
        DBG_PRINTF("%x, ", vn);
    }
    DBG_PRINTF("\n");
}

void picoquic_log_retry_packet(uint64_t log_cnxid64,
    uint8_t* bytes, picoquic_packet_header* ph)
{
    size_t byte_index = ph->offset;
    int token_length = 0;
    uint8_t odcil;
    uint8_t unused_cil;
    int payload_length = (int)(ph->payload_length);
    /* Decode ODCIL from bottom 4 bits of first byte */
    picoquic_parse_packet_header_cnxid_lengths(bytes[0], &unused_cil, &odcil);

    if ((int)odcil > payload_length) {
        picoquic_log_prefix_initial_cid64(log_cnxid64);
        DBG_PRINTF("packet too short, ODCIL: %x (%d), only %d bytes available.\n", 
            bytes[0]&0x0F, odcil, payload_length);
    } else {
        /* Dump the old connection ID */
        picoquic_log_prefix_initial_cid64(log_cnxid64);
        DBG_PRINTF("    ODCIL: <");
        for (uint8_t i = 0; i < odcil; i++) {
            DBG_PRINTF("%02x", bytes[byte_index++]);
        }

        token_length = payload_length - odcil;
        DBG_PRINTF(">, Token length: %d\n", token_length);
        /* Print the token or an error */
        if (token_length > 0) {
            int printed_length = (token_length > 16) ? 16 : token_length; 
            picoquic_log_prefix_initial_cid64(log_cnxid64);
            DBG_PRINTF("    Token: ");
            for (uint8_t i = 0; i < printed_length; i++) {
                DBG_PRINTF("%02x", bytes[byte_index++]);
            }
            if (printed_length < token_length) {
                DBG_PRINTF("...");
            }
            DBG_PRINTF("\n");
        }
    }
    DBG_PRINTF("\n");
}

size_t picoquic_log_stream_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index;
    uint64_t stream_id;
    size_t data_length;
    uint64_t offset;
    int fin;
    int ret = 0;

    int suspended = debug_printf_reset(1);
    ret = picoquic_parse_stream_header(bytes, bytes_max,
        &stream_id, &offset, &data_length, &fin, &byte_index);
    (void)debug_printf_reset(suspended);

    if (ret != 0)
        return bytes_max;

    DBG_PRINTF("    Stream %lu%lu, offset %lu%lu, length %d, fin = %d", (uint32_t)( stream_id >> 32),
        (uint32_t)stream_id, (uint32_t)( offset >> 32), (uint32_t)offset, (int)data_length, fin);

    DBG_PRINTF(": ");
    for (size_t i = 0; i < 8 && i < data_length; i++) {
        DBG_PRINTF("%02x", bytes[byte_index + i]);
    }
    DBG_PRINTF("%s\n", (data_length > 8) ? "..." : "");

    return byte_index + data_length;
}

size_t picoquic_log_ack_frame(uint64_t cnx_id64, uint8_t* bytes, size_t bytes_max, int is_ecn)
{
    size_t byte_index;
    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t ecnx3[3];

    int suspended = debug_printf_reset(1);

    int ret = picoquic_parse_ack_header(bytes, bytes_max, &num_block, NULL,
        &largest, &ack_delay, &byte_index, 0);

    (void)debug_printf_reset(suspended);

    if (ret != 0)
        return bytes_max;

    /* Now that the size is good, print it */
    if (is_ecn) {
        DBG_PRINTF("    ACK_ECN (nb=%u)", (int)num_block);
    }
    else {
        DBG_PRINTF("    ACK (nb=%u)", (int)num_block);
    }

    /* decoding the acks */

    for (;;) {
        uint64_t range;
        uint64_t block_to_block;

        if (byte_index >= bytes_max) {
            syslog(LOG_ERROR, "    Malformed ACK RANGE, %d blocks remain.\n", (int)num_block);
            break;
        }

        size_t l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &range);
        if (l_range == 0) {
            byte_index = bytes_max;
            syslog(LOG_ERROR, "    Malformed ACK RANGE, requires %d bytes out of %d", (int)picoquic_varint_skip(bytes),
                (int)(bytes_max - byte_index));
            break;
        } else {
            byte_index += l_range;
        }

        range++;

        if (largest + 1 < range) {
            DBG_PRINTF("\n");
            if (cnx_id64 != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            syslog(LOG_ERROR, "    ack range error: largest=%lu%lu, range=%lu%lu",
                (uint32_t)( largest >> 32), (uint32_t)largest, (uint32_t)( range >> 32), (uint32_t)range);
            byte_index = bytes_max;
            break;
        }

        if (range <= 1)
            DBG_PRINTF(", %lu%lu", (uint32_t)( largest >> 32), (uint32_t)largest);
        else
            DBG_PRINTF(", %lu%lu-%lu%lu", (uint32_t)((largest - range + 1) >> 32), (uint32_t)(largest - range + 1),
                (uint32_t)( largest >> 32), (uint32_t)largest);

        if (num_block-- == 0)
            break;

        /* Skip the gap */

        if (byte_index >= bytes_max) {
            DBG_PRINTF("\n");
            if (cnx_id64 != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            syslog(LOG_ERROR, "    Malformed ACK GAP, %d blocks remain.", (int)num_block);
            byte_index = bytes_max;
            break;
        } else {
            size_t l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &block_to_block);
            if (l_gap == 0) {
                byte_index = bytes_max;
                DBG_PRINTF("\n");
                if (cnx_id64 != 0) {
                    DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                }
                syslog(LOG_ERROR, "    Malformed ACK GAP, requires %d bytes out of %d", (int)picoquic_varint_skip(bytes),
                    (int)(bytes_max - byte_index));
                break;
            } else {
                byte_index += l_gap;
                block_to_block += 1;
                block_to_block += range;
            }
        }

        if (largest < block_to_block) {
            DBG_PRINTF("\n");
            if (cnx_id64 != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            syslog(LOG_ERROR, "    ack gap error: largest=%lu%lu, range=%lu%lu, gap=%lu%lu",
                (uint32_t)( largest >> 32), (uint32_t)largest, (uint32_t)( range >> 32), (uint32_t)range,
                (uint32_t)( (block_to_block - range) >> 32), (uint32_t)(block_to_block - range));
            byte_index = bytes_max;
            break;
        }

        largest -= block_to_block;
    }

    if (is_ecn) {
        /* Decode the ecn counts */
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            size_t l_ecnx = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &ecnx3[ecnx]);

            if (l_ecnx == 0) {
                syslog(LOG_ERROR, ", incorrect ECN encoding");
                byte_index = bytes_max;
                break;
            }
            else {
                byte_index += l_ecnx;
            }
        }

        DBG_PRINTF(", ect0=%lu, ect1=%lu, ce=%lu\n", (uint32_t)( ecnx3[0] >> 32), (uint32_t)ecnx3[0],
            (uint32_t)( ecnx3[1] >> 32), (uint32_t)ecnx3[1], (uint32_t)( ecnx3[2] >> 32), (uint32_t)ecnx3[2]);
    } else {
        DBG_PRINTF("\n");
    }

    return byte_index;
}

size_t picoquic_log_reset_stream_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t stream_id = 0;
    uint32_t error_code = 0;
    uint64_t offset = 0;

    size_t l1 = 0, l2 = 0;
    if (bytes_max > 2) {
        l1 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &stream_id);
        byte_index += l1;
        if (l1 > 0 && bytes_max >= byte_index + 3) {
            error_code = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
            l2 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &offset);
            byte_index += l2;
        }
    }

    if (l1 == 0 || l2 == 0) {
        syslog(LOG_ERROR, "    Malformed RESET STREAM, requires %d bytes out of %d\n", (int)(byte_index + ((l1 == 0) ? (picoquic_varint_skip(bytes + 1) + 3) : picoquic_varint_skip(bytes + byte_index))),
            (int)bytes_max);
        byte_index = bytes_max;
    } else {
        DBG_PRINTF("    RESET STREAM %lu%lu, Error 0x%08x, Offset 0x%lx%lx.\n",
            (uint32_t)(stream_id >> 32), (uint32_t)stream_id, error_code,
            (uint32_t)(offset >> 32), (uint32_t)offset);
    }

    return byte_index;
}

size_t picoquic_log_stop_sending_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1) + 2;
    uint64_t stream_id;
    uint32_t error_code;

    if (min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed STOP SENDING, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &stream_id);
    error_code = PICOPARSE_16(bytes + byte_index);
    byte_index += 2;

    syslog(LOG_ERROR, "    STOP SENDING %d (0x%08x), Error 0x%x.\n",
        (uint32_t)stream_id, (uint32_t)stream_id, error_code);

    return byte_index;
}

size_t picoquic_log_generic_close_frame(uint8_t* bytes, size_t bytes_max, uint8_t ftype, uint64_t cnx_id64)
{
    size_t byte_index = 1;
    uint32_t error_code = 0;
    uint64_t string_length = 0;
    uint64_t offending_frame_type = 0;
    size_t lf = 0;
    size_t l1 = 0;

    if (bytes_max >= 4) {
        error_code = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        if (ftype == picoquic_frame_type_connection_close) {
            lf = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &offending_frame_type);
            if (lf == 0) {
                byte_index = bytes_max;
            }
            else {
                byte_index += lf;
            }
        }
        if (ftype != picoquic_frame_type_connection_close || lf != 0) {
            l1 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &string_length);
        }
    }

    if (l1 == 0) {
        syslog(LOG_ERROR, "    Malformed %s, requires %d bytes out of %d\n",
            picoquic_log_frame_names(ftype), 
            (int)(byte_index + picoquic_varint_skip(bytes + 3)), (int)bytes_max);
        byte_index = bytes_max;
    }
    else {
        byte_index += l1;

        DBG_PRINTF("    %s, Error 0x%04x, ", picoquic_log_frame_names(ftype), error_code);
        if (ftype == picoquic_frame_type_connection_close && 
            offending_frame_type != 0) {
            syslog(LOG_ERROR, "Offending frame %lx%lx\n",
                (uint32_t)(offending_frame_type >> 32), (uint32_t)offending_frame_type);
        }
        DBG_PRINTF("Reason length %lu%lu\n", (uint32_t)(string_length >> 32), (uint32_t)string_length);
        if (byte_index + string_length > bytes_max) {
            syslog(LOG_ERROR, "    Malformed %s, requires %lu%lu bytes out of %lu%lu\n",
                picoquic_log_frame_names(ftype), (uint32_t)((byte_index + string_length) >> 32),
                (uint32_t)(byte_index + string_length), (uint32_t)(bytes_max >> 32), (uint32_t)bytes_max);
            byte_index = bytes_max;
        }
        else if (string_length > 0) {
            /* Print the UTF8 string */
            char reason_string[49];
            uint64_t printed_length = (string_length > 48) ? 48 : string_length;

            for (uint32_t i = 0; i < printed_length; i++) {
                int c = bytes[byte_index + i];

                if (c < 0x20 || c > 0x7E) {
                    c = '.';
                }
                reason_string[i] = (char) c;
            }
            reason_string[printed_length] = 0;

            if (cnx_id64 != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }

            DBG_PRINTF("        Reason: %s", reason_string);
            if (string_length > printed_length) {
                DBG_PRINTF("...");
            }
            DBG_PRINTF("\n");

            byte_index += (size_t)string_length;
        }
    }

    return byte_index;
}

size_t picoquic_log_connection_close_frame(uint8_t* bytes, size_t bytes_max, uint64_t cnx_id64)
{
    return picoquic_log_generic_close_frame(bytes, bytes_max, picoquic_frame_type_connection_close, cnx_id64);
}

size_t picoquic_log_application_close_frame(uint8_t* bytes, size_t bytes_max, uint64_t cnx_id64)
{
    return picoquic_log_generic_close_frame(bytes, bytes_max, picoquic_frame_type_application_close, cnx_id64);
}

size_t picoquic_log_max_data_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t max_data;

    size_t l1 = picoquic_varint_decode(bytes + 1, bytes_max - 1, &max_data);

    if (1 + l1 > bytes_max) {
        syslog(LOG_ERROR, "    Malformed MAX DATA, requires %d bytes out of %d\n", (int)(1 + l1), (int)bytes_max);
        return bytes_max;
    } else {
        byte_index = 1 + l1;
    }

    DBG_PRINTF("    MAX DATA: 0x%lx%lx.\n", (uint32_t)( max_data >> 32), (uint32_t)max_data);

    return byte_index;
}

size_t picoquic_log_max_stream_data_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t stream_id;
    uint64_t max_data;

    size_t l1 = picoquic_varint_decode(bytes + 1, bytes_max - 1, &stream_id);
    size_t l2 = picoquic_varint_decode(bytes + 1 + l1, bytes_max - 1 - l1, &max_data);

    if (l1 == 0 || l2 == 0) {
        syslog(LOG_ERROR, "    Malformed MAX STREAM DATA, requires %d bytes out of %d\n",
            (int)(1 + l1 + l2), (int)bytes_max);
        return bytes_max;
    } else {
        byte_index = 1 + l1 + l2;
    }

    DBG_PRINTF("    MAX STREAM DATA, Stream: %lu%lu, max data: 0x%lx%lx.\n",
        (uint32_t)( stream_id >> 32), (uint32_t) stream_id, (uint32_t)( max_data >> 32), (uint32_t)max_data);

    return byte_index;
}

size_t picoquic_log_max_stream_id_frame(uint8_t* bytes, size_t bytes_max, uint8_t frame_id)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1);
    uint64_t rank;

    if (min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed %s, requires %d bytes out of %d\n", picoquic_log_frame_names(frame_id),
            (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &rank);

    DBG_PRINTF("    %s: %lu%lu.\n", picoquic_log_frame_names(frame_id),
        (uint32_t)( rank >> 32), (uint32_t)rank);

    return byte_index;
}

size_t picoquic_log_blocked_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1);
    uint64_t blocked_offset = 0;

    if (min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed BLOCKED, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &blocked_offset);

    DBG_PRINTF("    BLOCKED: offset %lu%lu.\n",
        (uint32_t)( blocked_offset >> 32), (uint32_t)blocked_offset);

    return byte_index;
}

size_t picoquic_log_stream_blocked_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1);
    uint64_t blocked_stream_id;

    if (min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed STREAM BLOCKED, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &blocked_stream_id);
    byte_index += picoquic_varint_skip(&bytes[byte_index]);

    DBG_PRINTF("    STREAM BLOCKED: %.\n", (uint32_t)( blocked_stream_id >> 32), (uint32_t)blocked_stream_id);

    return byte_index;
}

size_t picoquic_log_streams_blocked_frame(uint8_t* bytes, size_t bytes_max, uint8_t frame_id)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1);
    uint64_t blocked_stream_rank;

    if (min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed %s frame, requires %d bytes out of %d\n", picoquic_log_frame_names(frame_id),
            (int)min_size, (int)bytes_max);
        byte_index =  bytes_max;
    }
    else {
        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &blocked_stream_rank);
        DBG_PRINTF("    %s: %ld%ld\n", picoquic_log_frame_names(frame_id),
            (uint32_t)( blocked_stream_rank >> 32), (uint32_t) blocked_stream_rank);
    }

    return byte_index;
}

size_t picoquic_log_new_connection_id_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    size_t min_size = 2 + 16;
    uint64_t sequence;
    picoquic_connection_id_t new_cnx_id = picoquic_null_connection_id;
    uint8_t l_cid = 0;
    size_t l_seq = 0;

    l_seq = picoquic_varint_decode(&bytes[byte_index], bytes_max, &sequence);
    min_size += l_seq;
    byte_index += l_seq;

    if (byte_index < bytes_max) {
        l_cid = bytes[byte_index++];
    }
    min_size += l_cid;

    if (l_seq == 0 || min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed NEW CONNECTION ID, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        byte_index = bytes_max;
    }
    else {
        byte_index += picoquic_parse_connection_id(bytes + byte_index, l_cid, &new_cnx_id);
        DBG_PRINTF("    NEW CONNECTION ID[%d]: 0x", (int)sequence);
        for (int x = 0; x < new_cnx_id.id_len; x++) {
            DBG_PRINTF("%02x", new_cnx_id.id[x]);
        }
        DBG_PRINTF(", ");
        for (int x = 0; x < 16; x++) {
            DBG_PRINTF("%02x", bytes[byte_index++]);
        }
        DBG_PRINTF("\n");
        DBG_FLUSH();
    }

    return byte_index;
}

size_t picoquic_log_retire_connection_id_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t sequence = 0;
    size_t l_seq = 0;


    if (bytes_max > byte_index) {
        l_seq = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &sequence);
        byte_index += l_seq;
    }

    if (l_seq == 0 || byte_index > bytes_max) {
        syslog(LOG_ERROR, "    Malformed RETIRE CONNECTION ID, requires %d bytes out of %d\n", (int)(byte_index + ((l_seq == 0)?1:0)), (int)bytes_max);
        byte_index = bytes_max;
    }
    else {
        DBG_PRINTF("    RETIRE CONNECTION ID[%d]\n", (int)sequence);
    }

    return byte_index;
}

size_t picoquic_log_new_token_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    size_t min_size = 1;
    size_t l_toklen = 0;
    uint64_t toklen = 0;

    l_toklen = picoquic_varint_decode(&bytes[byte_index], bytes_max, &toklen);

    min_size += l_toklen + (size_t)toklen;

    if (l_toklen == 0 || min_size > bytes_max) {
        syslog(LOG_ERROR, "    Malformed NEW CONNECTION ID, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    } else {
        byte_index += l_toklen;
        DBG_PRINTF("    NEW TOKEN[%d]: 0x", (int)toklen);
        for (int x = 0; x < toklen && x < 16; x++) {
            DBG_PRINTF("%02x", bytes[byte_index + x]);
        }
        byte_index += (size_t)toklen;

        if (toklen > 16) {
            DBG_PRINTF("...");
        }
        DBG_PRINTF("\n");
    }

    return byte_index;
}

size_t picoquic_log_path_frame(uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    size_t challenge_length = 8;

    if (byte_index + challenge_length > bytes_max) {
        syslog(LOG_ERROR, "    Malformed %s frame, %d bytes needed, %d available\n",
            picoquic_log_frame_names(bytes[0]),
            (int)(challenge_length + 1), (int)bytes_max);
        byte_index = bytes_max;
    } else {
        DBG_PRINTF("    %s: ", picoquic_log_frame_names(bytes[0]));

        for (size_t i = 0; i < challenge_length; i++) {
            DBG_PRINTF("%02x", bytes[byte_index + i]);
        }

        DBG_PRINTF("\n");

        byte_index += challenge_length;
    }

    return byte_index;
}

size_t picoquic_log_crypto_hs_frame(uint8_t* bytes, size_t bytes_max)
{
    uint64_t offset=0;
    uint64_t data_length = 0;
    size_t byte_index = 1;
    size_t l_off = 0;
    size_t l_len = 0;

    DBG_FLUSH();
    if (bytes_max > byte_index) {
        l_off = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &offset);
        byte_index += l_off;
    }

    if (bytes_max > byte_index) {
        l_len = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &data_length);
        byte_index += l_len;
    }

    if (l_off == 0 || l_len == 0 || byte_index + data_length > bytes_max) {
        syslog(LOG_ERROR, "    Malformed Crypto HS frame.\n");
        byte_index = bytes_max;
    } else {
        DBG_PRINTF("    Crypto HS frame, offset %lu%lu, length %d",
         (uint32_t)(offset >> 32), (uint32_t)offset, (int)data_length);

        DBG_PRINTF(": ");
        for (size_t i = 0; i < 8 && i < data_length; i++) {
            DBG_PRINTF("%02x", bytes[byte_index + i]);
        }
        DBG_PRINTF("%s\n", (data_length > 8) ? "..." : "");
        DBG_FLUSH();
        byte_index += (size_t)data_length;
    }

    return byte_index;
}

void picoquic_log_frames(uint64_t cnx_id64, uint8_t* bytes, size_t length)
{
    size_t byte_index = 0;

    while (byte_index < length) {
        uint8_t frame_id = bytes[byte_index];

        picoquic_log_prefix_initial_cid64(cnx_id64);

        if (PICOQUIC_IN_RANGE(frame_id, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            byte_index += picoquic_log_stream_frame(bytes + byte_index, length - byte_index);
            continue;
        }

        switch (frame_id) {
        case picoquic_frame_type_ack:
            byte_index += picoquic_log_ack_frame(cnx_id64, bytes + byte_index, length - byte_index, 0);
            break;
        case picoquic_frame_type_ack_ecn:
            byte_index += picoquic_log_ack_frame(cnx_id64, bytes + byte_index, length - byte_index, 1);
            break;
        case picoquic_frame_type_retire_connection_id:
            byte_index += picoquic_log_retire_connection_id_frame(bytes + byte_index, length - byte_index);
            break;
        case picoquic_frame_type_padding:
        case picoquic_frame_type_ping: {
            int nb = 0;

            while (byte_index < length && bytes[byte_index] == frame_id) {
                byte_index++;
                nb++;
            }

            DBG_PRINTF("    %s, %d bytes\n", picoquic_log_frame_names(frame_id), nb);
            break;
        }
        case picoquic_frame_type_reset_stream: /* RST_STREAM */
            byte_index += picoquic_log_reset_stream_frame(bytes + byte_index, length - byte_index);
            break;
        case picoquic_frame_type_connection_close: /* CONNECTION_CLOSE */
            byte_index += picoquic_log_connection_close_frame(bytes + byte_index,
                length - byte_index, cnx_id64);
            break;
        case picoquic_frame_type_application_close:
            byte_index += picoquic_log_application_close_frame(bytes + byte_index,
                length - byte_index, cnx_id64);
            break;
        case picoquic_frame_type_max_data: /* MAX_DATA */
            byte_index += picoquic_log_max_data_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_max_stream_data: /* MAX_STREAM_DATA */
            byte_index += picoquic_log_max_stream_data_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_max_streams_bidir: /* MAX_STREAM_ID */
        case picoquic_frame_type_max_streams_unidir: /* MAX_STREAM_ID */
            byte_index += picoquic_log_max_stream_id_frame(bytes + byte_index,
                length - byte_index, frame_id);
            break;
        case picoquic_frame_type_data_blocked: /* BLOCKED */
            /* No payload */
            byte_index += picoquic_log_blocked_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_stream_data_blocked: /* STREAM_BLOCKED */
            byte_index += picoquic_log_stream_blocked_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_streams_blocked_bidir: /* STREAM_ID_NEEDED */
        case picoquic_frame_type_streams_blocked_unidir: /* STREAM_ID_NEEDED */
            byte_index += picoquic_log_streams_blocked_frame(bytes + byte_index,
                length - byte_index, frame_id);
            break;
        case picoquic_frame_type_new_connection_id: /* NEW_CONNECTION_ID */
            byte_index += picoquic_log_new_connection_id_frame(bytes + byte_index, length - byte_index);
            break;
        case picoquic_frame_type_stop_sending: /* STOP_SENDING */
            byte_index += picoquic_log_stop_sending_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_path_challenge:
            byte_index += picoquic_log_path_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_path_response:
            byte_index += picoquic_log_path_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_crypto_hs:
            byte_index += picoquic_log_crypto_hs_frame(bytes + byte_index,
                length - byte_index);
            break;
        case picoquic_frame_type_new_token:
            byte_index += picoquic_log_new_token_frame(bytes + byte_index, length - byte_index);
            break;
        default: {
            /* Not implemented yet! */
            uint64_t frame_id64;
            if (picoquic_varint_decode(bytes, length - byte_index, &frame_id64) > 0) {
                DBG_PRINTF("    Unknown frame, type: %lx\n", frame_id);
            } else {
                DBG_PRINTF("    Truncated frame type\n");
            }
            byte_index = length;
            break;
        }
        }
        DBG_FLUSH();
    }
}

void picoquic_log_decrypted_segment(int log_cnxid, picoquic_cnx_t* cnx,
    int receiving, picoquic_packet_header * ph, uint8_t* bytes, size_t length, int ret)
{
    uint64_t log_cnxid64 = 0;

    if (log_cnxid != 0) {
        if (cnx == NULL) {
            ph->pn64 = ph->pn;
            if (ret == 0) {
                if (ph->ptype == picoquic_packet_version_negotiation) {
                    log_cnxid64 = picoquic_val64_connection_id(ph->srce_cnx_id);
                }
                else {
                    log_cnxid64 = picoquic_val64_connection_id(ph->dest_cnx_id);
                }
            }
        }
        else {
            log_cnxid64 = picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx));
        }
    }
    /* Header */
    picoquic_log_packet_header(log_cnxid64, ph, receiving);

    if (ret != 0) {
        /* packet does parse or decrypt */
        picoquic_log_prefix_initial_cid64(log_cnxid64);

        if (ret == PICOQUIC_ERROR_STATELESS_RESET) {
            DBG_PRINTF("   Stateless reset.\n");
        }
        else {
            syslog(LOG_ERROR, "   Header or encryption error: %x.\n", ret);
        }
    }
    else if (ph->ptype == picoquic_packet_version_negotiation) {
        /* log version negotiation */
        picoquic_log_negotiation_packet(log_cnxid64, bytes, length, ph);
    }
    else if (ph->ptype == picoquic_packet_retry) {
        /* log version negotiation */
        picoquic_log_retry_packet(log_cnxid64, bytes, ph);
    }
    else if (ph->ptype != picoquic_packet_error) {
        /* log frames inside packet */
        picoquic_log_prefix_initial_cid64(log_cnxid64);
        DBG_PRINTF("    %s %d bytes\n", (receiving)?"Decrypted": "Prepared",
            (int)ph->payload_length);
        picoquic_log_frames(log_cnxid64, bytes + ph->offset, ph->payload_length);
    }
    DBG_PRINTF("\n");
    DBG_FLUSH();
}

void picoquic_log_outgoing_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    uint8_t * bytes,
    uint64_t sequence_number,
    uint32_t length,
    uint8_t* send_buffer, uint32_t send_length)
{
    picoquic_cnx_t* pcnx = cnx;
    picoquic_packet_header ph;
    uint32_t checksum_length = (cnx != NULL) ? picoquic_get_checksum_length(cnx, 0) : 16;
    struct sockaddr_in default_addr;
    int ret;

    memset(&default_addr, 0, sizeof(struct sockaddr_in));
    default_addr.sin_family = AF_INET;

    ret = picoquic_parse_packet_header((cnx == NULL) ? NULL : cnx->quic, send_buffer, send_length,
        ((cnx == NULL || cnx->path[0] == NULL) ? (struct sockaddr *)&default_addr :
        (struct sockaddr *)&cnx->path[0]->local_addr), &ph, &pcnx, 0);

    ph.pn64 = sequence_number;
    ph.pn = (uint32_t)ph.pn64;
    if (ph.ptype != picoquic_packet_retry) {
        if (ph.pn_offset != 0) {
            ph.offset = ph.pn_offset + 4; /* todo: should provide the actual length */
            ph.payload_length -= 4;
        }
    }
    if (ph.ptype != picoquic_packet_version_negotiation) {
        if (ph.payload_length > checksum_length) {
            ph.payload_length -= (uint16_t)checksum_length;
        }
        else {
            ph.payload_length = 0;
        }
    }
    /* log the segment. */
    picoquic_log_decrypted_segment(log_cnxid, cnx, 0, &ph, bytes, length, ret);
    DBG_FLUSH();
}

void picoquic_log_processing(picoquic_cnx_t* cnx, size_t length, int ret)
{
    DBG_PRINTF("Processed %d bytes, state = %d (%s), return %d\n\n", (int)length, cnx->cnx_state,
        picoquic_log_state_name(cnx->cnx_state), ret);
    DBG_FLUSH();
}

void picoquic_log_transport_extension_content(int log_cnxid, uint64_t cnx_id64, 
    uint8_t * bytes, size_t bytes_max, int client_mode, 
    uint32_t initial_version, uint32_t final_version)
{
    int ret = 0;
    size_t byte_index = 0;
    DBG_FLUSH();
    if (bytes_max < 256)
    {
        switch (client_mode) {
        case 0: // Client hello
            if (bytes_max < 4 + byte_index) {
                if (log_cnxid != 0) {
                    DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                }
                syslog(LOG_ERROR, "Malformed client extension, length %d < 4 bytes.\n", (int)(bytes_max - byte_index));
                ret = -1;
            }
            else {
                uint32_t proposed_version;
                proposed_version = PICOPARSE_32(bytes + byte_index);
                byte_index += 4;
                if (log_cnxid != 0) {
                    DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                }
                DBG_PRINTF("Proposed version: %08x\n", proposed_version);
            }
            break;
        case 1: // Server encrypted extension
        {
            if (log_cnxid != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            if (bytes_max < byte_index + 5) {
                syslog(LOG_ERROR, "Malformed server extension, length %d < 5 bytes.\n", (int)(bytes_max - byte_index));
                ret = -1;
            } else {
                uint32_t version;

                version = PICOPARSE_32(bytes + byte_index);
                byte_index += 4;

                DBG_PRINTF("Version: %08x\n", version);

                size_t supported_versions_size = bytes[byte_index++];

                if ((supported_versions_size & 3) != 0) {
                    if (log_cnxid != 0) {
                        DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                    }
                    syslog(LOG_ERROR, "Malformed extension, supported version size = %d, not multiple of 4.\n",
                        (uint32_t)supported_versions_size);
                    ret = -1;

                } else if (supported_versions_size > 252 || byte_index + supported_versions_size > bytes_max) {
                    if (log_cnxid != 0) {
                        DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                    }
                    syslog(LOG_ERROR, "    Malformed extension, supported version size = %d, max %d or 252\n",
                        (uint32_t)supported_versions_size, (int)(bytes_max - byte_index));
                    ret = -1;
                } else {
                    size_t nb_supported_versions = supported_versions_size / 4;

                    if (log_cnxid != 0) {
                        DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                    }
                    DBG_PRINTF("    Supported version (%d bytes):\n", (int)supported_versions_size);

                    for (size_t i = 0; i < nb_supported_versions; i++) {
                        uint32_t supported_version = PICOPARSE_32(bytes + byte_index);

                        byte_index += 4;
                        if (log_cnxid != 0) {
                            DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                        }
                        if (supported_version == initial_version && initial_version != final_version) {
                            DBG_PRINTF("        %08x (same as proposed!)\n", supported_version);
                        } else {
                            DBG_PRINTF("        %08x\n", supported_version);
                        }
                    }
                    DBG_FLUSH();
                }
            }
            break;
        }
        default: // New session ticket
            if (log_cnxid != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            DBG_PRINTF("Transport parameters in session ticket -- not supported!\n");
            ret = -1;
            break;
        }

        if (ret == 0)
        {
            if (byte_index + 2 > bytes_max) {
                if (log_cnxid != 0) {
                    DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                }
                syslog(LOG_ERROR, "    Malformed extension list, only %d byte avaliable.\n", (int)(bytes_max - byte_index));
                ret = -1;
            }
            else {
                uint16_t extensions_size = PICOPARSE_16(bytes + byte_index);
                size_t extensions_end;
                byte_index += 2;
                extensions_end = byte_index + extensions_size;

                if (extensions_end > bytes_max) {
                    if (log_cnxid != 0) {
                        DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                    }
                    DBG_PRINTF("    Extension list too long (%d bytes vs %d)\n",
                        (uint32_t)extensions_size, (uint32_t)(bytes_max - byte_index));
                }
                else {
                    if (log_cnxid != 0) {
                        DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                    }
                    DBG_PRINTF("    Extension list (%d bytes):\n",
                        (uint32_t)extensions_size);
                    while (ret == 0 && byte_index < extensions_end) {
                        if (byte_index + 4 > extensions_end) {
                            if (log_cnxid != 0) {
                                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                            }
                            syslog(LOG_ERROR, "        Malformed extension -- only %d bytes avaliable for type and length.\n",
                                (int)(extensions_end - byte_index));
                            ret = -1;
                        }
                        else {
                            uint16_t extension_type = PICOPARSE_16(bytes + byte_index);
                            uint16_t extension_length = PICOPARSE_16(bytes + byte_index + 2);
                            byte_index += 4;

                            if (log_cnxid != 0) {
                                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                            }
                            DBG_PRINTF("        Extension type: %d, length %d (0x%04x / 0x%04x), ",
                                extension_type, extension_length, extension_type, extension_length);

                            if (byte_index + extension_length > extensions_end) {
                                if (log_cnxid != 0) {
                                    DBG_PRINTF("\n%lx%lx: ", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
                                }
                                DBG_PRINTF("Malformed extension, only %d bytes available.\n", (int)(extensions_end - byte_index));
                                ret = -1;
                            }
                            else {
                                for (uint16_t i = 0; i < extension_length; i++) {
                                    DBG_PRINTF("%02x", bytes[byte_index++]);
                                }
                                DBG_PRINTF("\n");
                            }
                        }
                        DBG_FLUSH();
                    }
                }
            }
        }

        if (ret == 0 && byte_index < bytes_max) {
            if (log_cnxid != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            DBG_PRINTF("    Remaining bytes (%d)\n", (uint32_t)(bytes_max - byte_index));
        }
    }
    else {
        if (log_cnxid != 0) {
            DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
        }
        DBG_PRINTF("Received transport parameter TLS extension (%d bytes):\n", (uint32_t)bytes_max);
        if (log_cnxid != 0) {
            DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
        }
        DBG_PRINTF("    First bytes (%d):\n", (uint32_t)(bytes_max - byte_index));
    }

    if (ret == 0)
    {
        while (byte_index < bytes_max && byte_index < 128) {
            if (log_cnxid != 0) {
                DBG_PRINTF("%lx%lx:", (uint32_t)( cnx_id64 >> 32), (uint32_t)cnx_id64);
            }
            DBG_PRINTF("        ");
            for (int i = 0; i < 32 && byte_index < bytes_max && byte_index < 128; i++) {
                DBG_PRINTF("%02x", bytes[byte_index++]);
            }
            DBG_PRINTF("\n");
            DBG_FLUSH();
        }
    }
}

void picoquic_log_transport_extension(picoquic_cnx_t* cnx, int log_cnxid)
{
    uint8_t* bytes = NULL;
    size_t bytes_max = 0;
    int ext_received_return = 0;
    int client_mode = 1;
    char const* sni = picoquic_tls_get_sni(cnx);
    char const* alpn = picoquic_tls_get_negotiated_alpn(cnx);
    uint64_t cnx_id64 = (log_cnxid) ? picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)) : 0;

    picoquic_log_prefix_initial_cid64(cnx_id64);
    if (sni == NULL) {
        DBG_PRINTF("SNI not received.\n");
    } else {
        DBG_PRINTF("Received SNI: %s\n", sni);
    }

    picoquic_log_prefix_initial_cid64(cnx_id64);
    if (alpn == NULL) {
        DBG_PRINTF("ALPN not received.\n");
    } else {
        DBG_PRINTF("Received ALPN: %s\n", alpn);
    }

    picoquic_provide_received_transport_extensions(cnx,
        &bytes, &bytes_max, &ext_received_return, &client_mode);

    if (bytes_max == 0) {
        picoquic_log_prefix_initial_cid64(cnx_id64);
        DBG_PRINTF("Did not receive transport parameter TLS extension.\n");
    }
    else {
        picoquic_log_prefix_initial_cid64(cnx_id64);
        DBG_PRINTF("Received transport parameter TLS extension (%d bytes):\n", (uint32_t)bytes_max);

        picoquic_log_transport_extension_content(log_cnxid,
            picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)), bytes, bytes_max, client_mode,
            cnx->proposed_version, picoquic_supported_versions[cnx->version_index].version);
    }

    if (log_cnxid == 0) {
        DBG_PRINTF("\n");
    }
}

void picoquic_log_congestion_state(picoquic_cnx_t* cnx, uint64_t current_time)
{
    picoquic_path_t * path_x = cnx->path[0];

    DBG_PRINTF("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
    picoquic_log_time(cnx, current_time, "T= ", ", ");
    DBG_PRINTF("cwin: %d,", (int)path_x->cwin);
    DBG_PRINTF("flight: %d,", (int)path_x->bytes_in_transit);
    DBG_PRINTF("nb_ret: %d,", (int)cnx->nb_retransmission_total);
    DBG_PRINTF("rtt_min: %d,", (int)path_x->rtt_min);
    DBG_PRINTF("rtt: %d,", (int)path_x->smoothed_rtt);
    DBG_PRINTF("rtt_var: %d,", (int)path_x->rtt_variant);
    DBG_PRINTF("max_ack_delay: %d,", (int)path_x->max_ack_delay);
    DBG_PRINTF("state: %d\n", (int)cnx->cnx_state);
}

/*
    From TLS 1.3 spec:
   struct {
       uint32 ticket_lifetime;
       uint32 ticket_age_add;
       opaque ticket_nonce<0..255>;
       opaque ticket<1..2^16-1>;
       Extension extensions<0..2^16-2>;
   } NewSessionTicket;

   struct {
       ExtensionType extension_type;
       opaque extension_data<0..2^16-1>;
   } Extension;
*/
static void picoquic_log_tls_ticket(picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length)
{
    uint64_t cnx_id64 = picoquic_val64_connection_id(cnx_id);
    uint32_t lifetime = 0;
    uint32_t age_add = 0;
    uint8_t nonce_length = 0;
    uint16_t ticket_val_length = 0;
    uint16_t extension_length = 0;
    uint8_t* extension_ptr = NULL;
    uint16_t byte_index = 0;
    uint16_t min_length = 4 + 4 + 1 + 2 + 2;
    int ret = 0;

    if (ticket_length < min_length) {
        ret = -1;
    } else {
        lifetime = PICOPARSE_32(ticket);
        byte_index += 4;
        age_add = PICOPARSE_32(ticket + byte_index);
        byte_index += 4;
        nonce_length = ticket[byte_index++];
        min_length += nonce_length;
        if (ticket_length < min_length) {
            ret = -1;
        } else {
            byte_index += nonce_length;

            ticket_val_length = PICOPARSE_16(ticket + byte_index);
            byte_index += 2;
            min_length += ticket_val_length;
            if (ticket_length < min_length) {
                ret = -1;
            } else {
                byte_index += ticket_val_length;

                extension_length = PICOPARSE_16(ticket + byte_index);
                byte_index += 2;
                min_length += extension_length;
                if (ticket_length < min_length) {
                    ret = -1;
                } else {
                    extension_ptr = &ticket[byte_index];
                    if (ticket_length > min_length) {
                        ret = -2;
                    }
                }
            }
        }
    }

    if (ret == -1) {
        picoquic_log_prefix_initial_cid64(cnx_id64);
        syslog(LOG_ERROR, "Malformed ticket, length = %d, at least %d required.\n", ticket_length, min_length);
    }
    picoquic_log_prefix_initial_cid64(cnx_id64);
    DBG_PRINTF("lifetime = %d, age_add = %x, %d nonce, %d ticket, %d extensions.\n",
        lifetime, age_add, nonce_length, ticket_val_length, extension_length);

    if (extension_ptr != NULL) {
        uint16_t x_index = 0;

        picoquic_log_prefix_initial_cid64(cnx_id64);
        DBG_PRINTF("ticket extensions: ");

        while (x_index + 4 < extension_length) {
            uint16_t x_type = PICOPARSE_16(extension_ptr + x_index);
            uint16_t x_len = PICOPARSE_16(extension_ptr + x_index + 2);
            x_index += 4 + x_len;

            if (x_type == 42 && x_len == 4) {
                uint32_t ed_len = PICOPARSE_32(extension_ptr + x_index - 4);
                DBG_PRINTF("%d(ED: %x),", x_type, ed_len);
            } else {
                DBG_PRINTF("%d (%d bytes),", x_type, x_len);
            }

            if (x_index > extension_length) {
                DBG_PRINTF("\n");
                picoquic_log_prefix_initial_cid64(cnx_id64);
                syslog(LOG_ERROR, "malformed extensions, require %d bytes, not just %d", x_index, extension_length);
            }
        }

        DBG_PRINTF("\n");

        if (x_index < extension_length) {
            picoquic_log_prefix_initial_cid64(cnx_id64);
            DBG_PRINTF("%d extra bytes at the end of the extensions\n", extension_length - x_index);
        }
    }

    if (ret == -2) {
        picoquic_log_prefix_initial_cid64(cnx_id64);
        syslog(LOG_ERROR, "Malformed TLS ticket, %d extra bytes.\n", ticket_length - min_length);
    }
}

/*

From Picotls code:
uint64_t time;
uint16_t cipher_suite;
24 bit int = length of ticket;
<TLS ticket>
16 bit length
<resumption secret>

 */

void picoquic_log_picotls_ticket(picoquic_connection_id_t cnx_id, uint8_t* ticket, uint16_t ticket_length)
{
    uint64_t cnx_id64 = picoquic_val64_connection_id(cnx_id);
    uint64_t ticket_time = 0;
    uint16_t kx_id = 0;
    uint16_t suite_id = 0;
    uint32_t tls_ticket_length = 0;
    uint8_t* tls_ticket_ptr = NULL;
    uint16_t secret_length = 0;
    /* uint8_t* secret_ptr = NULL; */
    uint16_t byte_index = 0;
    uint32_t min_length = 8 + 2 + 3 + 2;
    int ret = 0;

    if (ticket_length < min_length) {
        ret = -1;
    } else {
        ticket_time = PICOPARSE_64(ticket);
        byte_index += 8;
        kx_id = PICOPARSE_16(ticket + byte_index);
        byte_index += 2;
        suite_id = PICOPARSE_16(ticket + byte_index);
        byte_index += 2;
        tls_ticket_length = PICOPARSE_24(ticket + byte_index);
        byte_index += 3;
        min_length += tls_ticket_length;
        if (ticket_length < min_length) {
            ret = -1;
        } else {
            tls_ticket_ptr = &ticket[byte_index];
            byte_index += (uint16_t) tls_ticket_length;

            secret_length = PICOPARSE_16(ticket + byte_index);
            min_length += secret_length + 2;
            if (ticket_length < min_length) {
                ret = -1;
            } else {
                /* secret_ptr = &ticket[byte_index]; */
                if (ticket_length > min_length) {
                    ret = -2;
                }
            }
        }
    }

    picoquic_log_prefix_initial_cid64(cnx_id64);
    DBG_PRINTF("ticket time = %lu%lu, kx = %x, suite = %x, %d ticket, %d secret.\n",
        (uint32_t)(ticket_time >> 32), (uint32_t)ticket_time,
        kx_id, suite_id, tls_ticket_length, secret_length);

    if (ret == -1) {
        picoquic_log_prefix_initial_cid64(cnx_id64);
        syslog(LOG_ERROR, "Malformed PTLS ticket, length = %d, at least %d required.\n", 
            ticket_length, min_length);
    } else {
        if (tls_ticket_length > 0 && tls_ticket_ptr != NULL) {
            picoquic_log_tls_ticket(cnx_id, tls_ticket_ptr, (uint16_t) tls_ticket_length);
        }
    }

    if (ret == -2) {
        picoquic_log_prefix_initial_cid64(cnx_id64);
        syslog(LOG_ERROR, "Malformed PTLS ticket, %d extra bytes.\n", ticket_length - min_length);
    }
}

/*
 * Check whether dumping of transmission traces is required. If it is,
 * the master context specifies the directory where to log the file.
 */

void picoquic_open_cc_dump(picoquic_cnx_t * cnx)
{
    int ret = 0;

    if (cnx->cc_log != NULL) {
        DBG_PRINTF("%s", "CC LOG File is already open!\n");
    } else if (cnx->quic->cc_log_dir != NULL) {
        char cc_log_file_name[512];
        char const * suffix = ".csv";
        const size_t suffix_len = strlen(suffix);
        size_t folder_length = strlen(cnx->quic->cc_log_dir);

        if (folder_length + 1 + 2*cnx->initial_cnxid.id_len + suffix_len + 1 > sizeof(cc_log_file_name)) {
            ret = -1;
        }
        else {
            size_t byte_index = 0;

            memcpy(cc_log_file_name, cnx->quic->cc_log_dir, folder_length);
            byte_index += folder_length;
#ifdef _WINDOWS
            cc_log_file_name[byte_index++] = '\\';
#else
            cc_log_file_name[byte_index++] = '/';
#endif
            for (size_t i = 0; ret == 0 && i < cnx->initial_cnxid.id_len; i++) {
#ifdef _WINDOWS
                ret = sprintf_s(&cc_log_file_name[byte_index], sizeof(cc_log_file_name) - byte_index, "%02x", cnx->initial_cnxid.id[i]) <= 0;
#else
                ret = sprintf(&cc_log_file_name[byte_index], "%02x", cnx->initial_cnxid.id[i]) <= 0;
#endif

                byte_index += 2;
            }

            if (ret == 0) {
                memcpy(&cc_log_file_name[byte_index], suffix, suffix_len);
                byte_index += suffix_len;
                cc_log_file_name[byte_index] = 0;
            }

            if (ret != 0) {
                syslog(LOG_NOTICE, "Cannot format file name into folder %s, id_len = %d\n", cnx->quic->cc_log_dir, cnx->initial_cnxid.id_len);
            }
        }

        if (ret == 0) {

#ifdef _WINDOWS
            errno_t err = fopen_s(&cnx->cc_log, cc_log_file_name, "w");
            if (err != 0 || cnx->cc_log == NULL) {
                ret = -1;
            }
#else
            cnx->cc_log = fopen(cc_log_file_name, "w");
            if (cnx->cc_log == NULL) {
                ret = -1;
            }
#endif
            if (ret != 0) {
                syslog(LOG_NOTICE, "Cannot open file %s for write.\n", cc_log_file_name);
            } else {
                /* TODO: maintain the list of headers as debugging data is added */
                ret |= fprintf(cnx->cc_log, "time, ") <= 0;
                ret |= fprintf(cnx->cc_log, "sequence, ") <= 0;
                ret |= fprintf(cnx->cc_log, "highest ack, ") <= 0;
                ret |= fprintf(cnx->cc_log, "high ack time, ") <= 0;
                ret |= fprintf(cnx->cc_log, "last time ack, ") <= 0;
                ret |= fprintf(cnx->cc_log, "cwin, ") <= 0;
                ret |= fprintf(cnx->cc_log, "SRTT, ") <= 0;
                ret |= fprintf(cnx->cc_log, "RTT min, ") <= 0;
                ret |= fprintf(cnx->cc_log, "Send MTU, ") <= 0;
                ret |= fprintf(cnx->cc_log, "pacing packet time(us), ") <= 0;
                ret |= fprintf(cnx->cc_log, "nb retrans, ") <= 0;
                ret |= fprintf(cnx->cc_log, "nb spurious, ") <= 0;
                ret |= fprintf(cnx->cc_log, "cwin blkd, ") <= 0;
                ret |= fprintf(cnx->cc_log, "flow blkd, ") <= 0;
                ret |= fprintf(cnx->cc_log, "stream blkd, ") <= 0;

                ret |= fprintf(cnx->cc_log, "\n") <= 0;

                if (ret != 0) {
                    syslog(LOG_NOTICE, "Cannot write header for file %s.\n", cc_log_file_name);
                    picoquic_close_cc_dump(cnx);
                }
            }
        }
    }
}

void picoquic_close_cc_dump(picoquic_cnx_t * cnx)
{
    if (cnx->cc_log != NULL) {
        (void) fclose(cnx->cc_log);
        cnx->cc_log = NULL;
    }
}

/*
 * Log the state of the congestion management, retransmission, etc.
 * Call either just after processing a received packet, or just after
 * sending a packet.
 */

void picoquic_cc_dump(picoquic_cnx_t * cnx, uint64_t current_time)
{
    int ret = 0;

    if (cnx->cc_log == NULL) {
        return;
    }

    /* TODO: complete list of tracked data as needed for debugging */
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)current_time) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->pkt_ctx[picoquic_packet_context_application].send_sequence) <= 0;
    ret |= fprintf(cnx->cc_log, "%lld, ", (long long)((int64_t)cnx->pkt_ctx[picoquic_packet_context_application].highest_acknowledged)) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->pkt_ctx[picoquic_packet_context_application].highest_acknowledged_time) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->pkt_ctx[picoquic_packet_context_application].latest_time_acknowledged) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->path[0]->cwin) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->path[0]->smoothed_rtt) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->path[0]->rtt_min) <= 0;
    ret |= fprintf(cnx->cc_log, "%u, ", cnx->path[0]->send_mtu) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->path[0]->pacing_packet_time_microsec) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->nb_retransmission_total) <= 0;
    ret |= fprintf(cnx->cc_log, "%llu, ", (unsigned long long)cnx->nb_spurious) <= 0;
    ret |= fprintf(cnx->cc_log, "%d, ", cnx->cwin_blocked) <= 0;
    ret |= fprintf(cnx->cc_log, "%d, ", cnx->flow_blocked) <= 0;
    ret |= fprintf(cnx->cc_log, "%d, ", cnx->stream_blocked) <= 0;
    ret |= fprintf(cnx->cc_log, "\n") <= 0;
    cnx->cwin_blocked = 0;
    cnx->flow_blocked = 0;
    cnx->stream_blocked = 0;

    if (ret != 0) {
        picoquic_close_cc_dump(cnx);
    }
}
#endif
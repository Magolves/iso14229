#if defined(UDS_TP_DOIP)
/**
 * @file doip_client.c
 * @brief ISO 13400 (DoIP) Transport Layer - Client Implementation
 * @details DoIP TCP transport layer client for UDS (ISO 14229)
 *
 *
 * @note This is a simplified implementation focusing on TCP diagnostic messages.
 *       UDP vehicle discovery is not included.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "doip_client.h"
#include "log.h"

/**
 * @brief Create and initialize DoIP header
 */
static void doip_header_init(DoIPHeader_t *header, uint16_t payload_type, uint32_t payload_length) {
    header->protocol_version = DOIP_PROTOCOL_VERSION;
    header->protocol_version_inv = DOIP_PROTOCOL_VERSION_INV;
    header->payload_type = htons(payload_type);
    header->payload_length = htonl(payload_length);
}

#define doip_change_state(t,s) {\
    if (_doip_change_state((t),(s))) {\
        UDS_LOGI(__FILE__, "DoIP: State change to %d (line %d)", (s), __LINE__);\
    }\
}

/**
 * @brief Change DoIP client state
 * @param tp DoIP client context
 * @param new_state New state to set
 * @return true if state changed, false if same state
 */
static bool _doip_change_state(DoIPClient_t *tp, DoIPClientState_t new_state) {
    if (tp->state == new_state)
        return false;

    //UDS_LOGI(__FILE__, "DoIP: State change %d -> %d", tp->state, new_state);
    tp->state = new_state;
    return true;
}

static void doip_log_poll_state(UDSTpStatus_t status, const char* msg) {
    // Currently no timed states to handle
    char buf[10];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "----", 4);
    if (status & UDS_TP_IDLE) buf[0] = 'I';
    if (status & UDS_TP_SEND_IN_PROGRESS) buf[1] = 'S';
    if (status & UDS_TP_RECV_COMPLETE) buf[2] = 'R';
    if (status & UDS_TP_ERR) buf[3] = 'E';

    UDS_LOGV(__FILE__, "DoIP TP Poll Status: [%s/%d] (%s) ()", buf, status, msg ? msg : "");
}

/**
 * @brief Parse DoIP header from buffer
 */
static bool doip_header_parse(const uint8_t *buffer, DoIPHeader_t *header) {
    if (!buffer || !header) {
        return false;
    }

    memcpy(header, buffer, sizeof(DoIPHeader_t));
    header->payload_type = ntohs(header->payload_type);
    header->payload_length = ntohl(header->payload_length);

    /* Validate protocol version */
    if (header->protocol_version != DOIP_PROTOCOL_VERSION ||
        header->protocol_version_inv != DOIP_PROTOCOL_VERSION_INV) {
        return false;
    }

    return true;
}

/**
 * @brief Send DoIP message
 */
static int doip_send_message(DoIPClient_t *tp, uint16_t payload_type, const uint8_t *payload,
                             uint32_t payload_len) {
    uint8_t buffer[DOIP_BUFFER_SIZE];
    DoIPHeader_t *header = (DoIPHeader_t *)buffer;

    if (DOIP_HEADER_SIZE + payload_len > DOIP_BUFFER_SIZE) {
        return -1;
    }

    doip_header_init(header, payload_type, payload_len);

    if (payload && payload_len > 0) {
        memcpy(buffer + DOIP_HEADER_SIZE, payload, payload_len);
    }

    ssize_t sent = send(tp->socket_fd, buffer, DOIP_HEADER_SIZE + payload_len, 0);
    if (sent < 0) {
        perror("send");
        return -1;
    }

    return sent - DOIP_HEADER_SIZE - DOIP_DIAG_HEADER_SIZE; /* Return number of payload bytes sent */
}

/**
 * @brief Handle routing activation response
 */
static void doip_handle_routing_activation_response(DoIPClient_t *tp, const uint8_t *payload,
                                                    uint32_t payload_len) {
    if (payload_len < 9) {
        UDS_LOGI(__FILE__, "DoIP: Invalid routing activation response length");
        doip_change_state(tp, DOIP_STATE_ERROR);
        return;
    }

    uint16_t client_sa = (payload[0] << 8) | payload[1];
    uint16_t server_sa = (payload[2] << 8) | payload[3];
    uint8_t response_code = payload[4];
    (void)client_sa; /* Validated implicitly by successful response */

    if (response_code == DOIP_ROUTING_ACTIVATION_RES_SUCCESS) {
        doip_change_state(tp, DOIP_STATE_READY_FOR_DIAG_REQUEST);
        UDS_LOGI(__FILE__, "DoIP: Routing activated (SA=0x%04X, TA=0x%04X)", tp->source_address,
                 server_sa);
    } else {
        UDS_LOGI(__FILE__, "DoIP: Routing activation failed (code=0x%02X)", response_code);
        doip_change_state(tp, DOIP_STATE_ERROR);
    }
}

/**
 * @brief Handle alive check response
 */
static void doip_handle_alive_check_response(DoIPClient_t *tp, const uint8_t *payload,
                                             uint32_t payload_len) {
    if (payload_len < 2) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    UDS_LOGI(__FILE__, "DoIP: Alive check response from 0x%04X", source_address);
}

/**
 * @brief Handle diagnostic message positive ACK
 */
static void doip_handle_diag_pos_ack(DoIPClient_t *tp, const uint8_t *payload,
                                     uint32_t payload_len) {
    if (payload_len < 5) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    uint16_t target_address = (payload[2] << 8) | payload[3];
    uint8_t ack_code = payload[4];

    tp->diag_ack_received = true;

    UDS_LOGI(__FILE__, "DoIP: Diagnostic message ACK (SA=0x%04X, TA=0x%04X, code=0x%02X)",
             source_address, target_address, ack_code);
}

/**
 * @brief Handle diagnostic message negative ACK
 */
static void doip_handle_diag_neg_ack(DoIPClient_t *tp, const uint8_t *payload,
                                     uint32_t payload_len) {
    if (payload_len < 5) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    uint16_t target_address = (payload[2] << 8) | payload[3];
    uint8_t nack_code = payload[4];

    tp->diag_nack_received = true;
    tp->diag_nack_code = nack_code;

    UDS_LOGI(__FILE__, "DoIP: Diagnostic message NACK (SA=0x%04X, TA=0x%04X, code=0x%02X)",
             source_address, target_address, nack_code);
}

/**
 * @brief Handle diagnostic message (response from server)
 */
static void doip_handle_diag_message(DoIPClient_t *tp, const uint8_t *payload,
                                     uint32_t payload_len) {
    if (payload_len < 4) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    uint16_t target_address = (payload[2] << 8) | payload[3];

    /* Verify target address matches our logical address */
    if (target_address != tp->source_address) {
        UDS_LOGI(__FILE__, "DoIP: Received diagnostic message for different TA=0x%04X",
                 target_address);
        return;
    }

    /* Store UDS response data in separate buffer for doip_tp_recv to retrieve */
    if (payload_len > DOIP_DIAG_HEADER_SIZE) {
        const uint8_t *uds_data = payload + DOIP_DIAG_HEADER_SIZE;
        size_t uds_len = payload_len - DOIP_DIAG_HEADER_SIZE;

        /* Copy UDS data to uds_response buffer */
        if (uds_len <= DOIP_BUFFER_SIZE) {
            memcpy(tp->uds_response, uds_data, uds_len);
            tp->uds_response_len = uds_len;
            UDS_LOGI(__FILE__, "DoIP: Stored diagnostic response (%zu bytes) from SA=0x%04X",
                     uds_len, source_address);
        } else {
            UDS_LOGE(__FILE__, "DoIP: Diagnostic response too large (%zu bytes)", uds_len);
        }
    }
}

/**
 * @brief Process received DoIP message
 */
static void doip_process_message(DoIPClient_t *tp, const DoIPHeader_t *header,
                                 const uint8_t *payload) {
    switch (header->payload_type) {
    case DOIP_PAYLOAD_TYPE_ROUTING_ACTIVATION_RES:
        doip_handle_routing_activation_response(tp, payload, header->payload_length);
        break;

    case DOIP_PAYLOAD_TYPE_ALIVE_CHECK_RES: // TODO: must be a response!
        doip_handle_alive_check_response(tp, payload, header->payload_length);
        break;

    case DOIP_PAYLOAD_TYPE_DIAG_MESSAGE_POS_ACK:
        doip_handle_diag_pos_ack(tp, payload, header->payload_length);
        break;

    case DOIP_PAYLOAD_TYPE_DIAG_MESSAGE_NEG_ACK:
        doip_handle_diag_neg_ack(tp, payload, header->payload_length);
        break;

    case DOIP_PAYLOAD_TYPE_DIAG_MESSAGE:
        doip_handle_diag_message(tp, payload, header->payload_length);
        break;

    default:
        UDS_LOGI(__FILE__, "DoIP: Unknown payload type 0x%04X", header->payload_type);
        break;
    }
}

/**
 * @brief Receive and process data
 */
static int doip_receive_data(DoIPClient_t *tp, int timeout_ms) {
    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(tp->socket_fd, &readfds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(tp->socket_fd + 1, &readfds, NULL, NULL, &tv);
    if (ret < 0) {
        perror("select");
        return -1;
    }

    if (ret == 0) {
        return 0; /* Timeout */
    }

    ssize_t bytes_read =
        recv(tp->socket_fd, tp->rx_buffer + tp->rx_offset, DOIP_BUFFER_SIZE - tp->rx_offset, 0);

    if (bytes_read <= 0) {
        if (bytes_read == 0) {
            UDS_LOGE(__FILE__, "DoIP: Server disconnected");
        } else {
            perror("recv");
        }
        doip_change_state(tp, DOIP_STATE_DISCONNECTED);
        return -1;
    }

    UDS_LOGI(__FILE__, "DoIP: Received %zd bytes", bytes_read);
    UDS_LOG_SDU(__FILE__, tp->rx_buffer + tp->rx_offset, bytes_read, NULL);

    tp->rx_offset += bytes_read;
    /* Process complete DoIP messages */
    while (tp->rx_offset >= DOIP_HEADER_SIZE) {
        DoIPHeader_t header;
        if (!doip_header_parse(tp->rx_buffer, &header)) {
            UDS_LOGE(__FILE__, "DoIP: Invalid header");
            doip_change_state(tp, DOIP_STATE_ERROR);
            return -1;
        }

        size_t total_msg_size = DOIP_HEADER_SIZE + header.payload_length;

        if (tp->rx_offset < total_msg_size) {
            /* Wait for more data */
            break;
        }

        /* Process message */
        const uint8_t *payload = tp->rx_buffer + DOIP_HEADER_SIZE;
        UDS_LOGI(__FILE__, "DoIP: Processing message type 0x%04X, length %u",
                 header.payload_type, header.payload_length);
        UDS_LOG_SDU(__FILE__, payload, header.payload_length, NULL);
        doip_process_message(tp, &header, payload);

        /* Remove processed message from buffer */
        if (tp->rx_offset > total_msg_size) {
            memmove(tp->rx_buffer, tp->rx_buffer + total_msg_size, tp->rx_offset - total_msg_size);
        }
        tp->rx_offset -= total_msg_size;
    }

    return bytes_read - DOIP_HEADER_SIZE - DOIP_DIAG_HEADER_SIZE;
}

/**
 * @brief Connect to DoIP server
 */
int doip_client_connect(DoIPClient_t *tp) {
    if (tp->state != DOIP_STATE_DISCONNECTED) {
        UDS_LOGE(__FILE__, "DoIP: Already connected or in error state");
        return -1;
    }

    /* Create TCP socket */
    tp->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tp->socket_fd < 0) {
        UDS_LOGE(__FILE__, "Socket error: %s", strerror(errno));
        return -1;
    }

    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = DOIP_DEFAULT_TIMEOUT_MS / 1000;
    tv.tv_usec = (DOIP_DEFAULT_TIMEOUT_MS % 1000) * 1000;
    setsockopt(tp->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Connect to server */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DOIP_TCP_PORT);

    if (inet_pton(AF_INET, tp->server_ip, &server_addr.sin_addr) <= 0) {
        UDS_LOGE(__FILE__, "DoIP: Invalid server IP address %s", tp->server_ip);
        close(tp->socket_fd);
        return -1;
    }

    if (connect(tp->socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        UDS_LOGE(__FILE__, "Connect error: %s (%s:%d)", strerror(errno), tp->server_ip,
                 tp->server_port);
        close(tp->socket_fd);
        return -1;
    }

    doip_change_state(tp, DOIP_STATE_CONNECTED);

    UDS_LOGI(__FILE__, "DoIP Client: Connected to %s:%d", tp->server_ip, DOIP_TCP_PORT);

    return 0;
}

/**
 * @brief Activate routing
 */
int doip_client_activate_routing(DoIPClient_t *tp) {
    if (tp->state != DOIP_STATE_CONNECTED) {
        UDS_LOGE(__FILE__, "DoIP: Not connected");
        return -1;
    }

    /* Build routing activation request */
    uint8_t payload[11];
    payload[0] = (tp->source_address >> 8) & 0xFF;
    payload[1] = tp->source_address & 0xFF;
    payload[2] = DOIP_ROUTING_ACTIVATION_TYPE;
    payload[3] = 0x00; /* Reserved */
    payload[4] = 0x00;
    payload[5] = 0x00;
    payload[6] = 0x00;

    /* Optional: OEM specific */
    payload[7] = 0x00;
    payload[8] = 0x00;
    payload[9] = 0x00;
    payload[10] = 0x00;

    if (doip_send_message(tp, DOIP_PAYLOAD_TYPE_ROUTING_ACTIVATION_REQ, payload, 11) < 0) {
        return -1;
    }

    doip_change_state(tp, DOIP_STATE_ROUTING_ACTIVATION_PENDING);

    /* Wait for routing activation response */
    int timeout_ms = DOIP_DEFAULT_TIMEOUT_MS;
    clock_t start = clock();

    while (tp->state == DOIP_STATE_ROUTING_ACTIVATION_PENDING) {
        int elapsed_ms = ((clock() - start) * 1000) / CLOCKS_PER_SEC;
        int remaining_ms = timeout_ms - elapsed_ms;

        if (remaining_ms <= 0) {
            UDS_LOGE(__FILE__, "DoIP: Routing activation timeout");
            doip_change_state(tp, DOIP_STATE_ERROR);
            return -1;
        }

        if (doip_receive_data(tp, remaining_ms) < 0) {
            return -1;
        }
    }

    if (tp->state != DOIP_STATE_READY_FOR_DIAG_REQUEST) {
        UDS_LOGE(__FILE__, "DoIP: Routing activation failed");
        return -1;
    }

    return 0;
}

/**
 * @brief Send diagnostic message
 */
int doip_client_send_diag_message(DoIPClient_t *tp, const uint8_t *data, size_t len) {
    // if (tp->state != DOIP_STATE_READY_FOR_DIAG_REQUEST) {
    //     UDS_LOGE(__FILE__, "DoIP: Routing not activated, state=%d", tp->state);
    //     return -1;
    // }

    /* Build diagnostic message payload */
    uint8_t payload[DOIP_BUFFER_SIZE];
    if (len + 4 > DOIP_BUFFER_SIZE) {
        UDS_LOGE(__FILE__, "DoIP: Message too large: %zu bytes > %d", len + 4, DOIP_BUFFER_SIZE);
        return -1;
    }

    payload[0] = (tp->source_address >> 8) & 0xFF;
    payload[1] = tp->source_address & 0xFF;
    payload[2] = (tp->target_address >> 8) & 0xFF;
    payload[3] = tp->target_address & 0xFF;
    memcpy(payload + 4, data, len);

    /* Reset ACK/NACK flags */
    tp->diag_ack_received = false;
    tp->diag_nack_received = false;

    int sent = doip_send_message(tp, DOIP_PAYLOAD_TYPE_DIAG_MESSAGE, payload, len + 4);

    if (sent < 0) {
        return -1;
    }

    doip_change_state(tp, DOIP_STATE_DIAG_MESSAGE_ACK_PENDING);

    /* Wait for ACK/NACK */
    int timeout_ms = 1000; /* 1 second for ACK */
    clock_t start = clock();

    while (!tp->diag_ack_received && !tp->diag_nack_received) {
        int elapsed_ms = ((clock() - start) * 1000) / CLOCKS_PER_SEC;
        int remaining_ms = timeout_ms - elapsed_ms;

        if (remaining_ms <= 0) {
            UDS_LOGE(__FILE__, "DoIP: Diagnostic message ACK timeout");
            return -1;
        }

        if (doip_receive_data(tp, remaining_ms) < 0) {
            return -1;
        }
    }

    if (tp->diag_nack_received) {
        doip_change_state(tp, DOIP_STATE_READY_FOR_DIAG_REQUEST); /* Reset state */
        UDS_LOGE(__FILE__, "DoIP: Diagnostic message rejected (NACK code=0x%02X)",
                 tp->diag_nack_code);
        return -1;
    }

    doip_change_state(tp, DOIP_STATE_DIAG_MESSAGE_RESPONSE_PENDING);

    return sent;
}

/**
 * @brief Process DoIP client events (call periodically)
 */
void doip_client_process(DoIPClient_t *tp, int timeout_ms) {
    if (tp->state == DOIP_STATE_READY_FOR_DIAG_REQUEST) {
        doip_receive_data(tp, timeout_ms);
    }
}

/**
 * @brief Send alive check request
 */
int doip_client_send_alive_check(DoIPClient_t *tp) {
    if (tp->state != DOIP_STATE_READY_FOR_DIAG_REQUEST) {
        UDS_LOGE(__FILE__, "DoIP: Not in activated state");
        return -1;
    }

    return doip_send_message(tp, DOIP_PAYLOAD_TYPE_ALIVE_CHECK_REQ, NULL, 0);
}

/**
 * @brief Disconnect from DoIP server
 */
void doip_client_disconnect(DoIPClient_t *tp) {
    if (tp->socket_fd >= 0) {
        close(tp->socket_fd);
        tp->socket_fd = -1;
    }

    doip_change_state(tp, DOIP_STATE_DISCONNECTED);
    tp->rx_offset = 0;
    UDS_LOGI(__FILE__, "DoIP Client: Disconnected");
}

////  FUNCTIONS FOR UDS INTERFACE ////

static ssize_t doip_tp_send(UDSTp_t *hdl, uint8_t *buf, size_t len, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    ssize_t ret = -1;
    DoIPClient_t *impl = (DoIPClient_t *)hdl;

    UDS_LOGD(__FILE__, "DoIP TP Send... len=%zu", len);
    ret = doip_client_send_diag_message(impl, buf, len);
    if (ret < 0) {
        UDS_LOGE(__FILE__, "DoIP TP Send Error");
    } else {
        UDS_LOG_SDU(__FILE__, buf, len, info);
        UDS_LOGD(__FILE__, "DoIP TP Send: Sent %zd bytes", ret);
    }
    return ret;
}

static ssize_t doip_tp_recv(UDSTp_t *hdl, uint8_t *buf, size_t bufsize, UDSSDU_t *info) {
    UDS_LOGI(__FILE__, "DoIP TP Recv: %p", hdl);
    UDS_ASSERT(hdl);
    UDS_ASSERT(buf);
    DoIPClient_t *impl = (DoIPClient_t *)hdl;

    // Try to receive any pending data (non-blocking poll inside)
    int rc = doip_receive_data(impl, 0);
    UDS_LOGI(__FILE__, "DoIP TP Recv: doip_receive_data returned %d", rc);

    // If we have a diagnostic response stored, return it
    if (impl->state == DOIP_STATE_DIAG_MESSAGE_RESPONSE_PENDING && impl->uds_response_len > 0) {
        size_t n = impl->uds_response_len;
        if (n > bufsize) {
            n = bufsize;
        }
        UDS_LOG_SDU(__FILE__, impl->uds_response, n, NULL);
        memcpy(buf, impl->uds_response, n);
        impl->uds_response_len = 0; // consume buffered data
        doip_change_state(impl, DOIP_STATE_READY_FOR_DIAG_REQUEST);

        // Populate SDU info if provided (physical addressing semantics on DoIP)
        if (info) {
            info->A_Mtype = UDS_A_MTYPE_DIAG;
            info->A_SA = impl->source_address;
            info->A_TA = impl->target_address;
            info->A_TA_Type = UDS_A_TA_TYPE_PHYSICAL;
            info->A_AE = UDS_TP_NOOP_ADDR;
        }

        UDS_LOG_SDU(__FILE__, buf, n, info);
        return (ssize_t)n;
    }

    return rc;
}

/**
 * @brief Poll DoIP transport layer status
 * @note Checks if the transport layer is ready to send/receive
 * @return UDS_TP_IDLE if idle, otherwise UDS_TP_SEND_IN_PROGRESS or UDS_TP_RECV_COMPLETE
 */
static UDSTpStatus_t doip_tp_poll(UDSTp_t *hdl) {
    UDS_ASSERT(hdl);
    UDSTpStatus_t status = 0;
    DoIPClient_t *impl = (DoIPClient_t *)hdl;
    UDS_LOGI(__FILE__, "DoIP TP Poll: %p (rx %zu bytes)", hdl, impl->uds_response_len);

    // Basic connectivity check
    if (impl->state == DOIP_STATE_DISCONNECTED || impl->socket_fd < 0) {
        status |= UDS_TP_ERR;
        doip_log_poll_state(status, "Disconnected");
        return status;
    }

    // Progress diagnostic transaction state based on ACK/NACK and response arrival.
    // 1) If waiting for ACK/NACK, mark send in progress until one arrives.
    if (impl->state == DOIP_STATE_DIAG_MESSAGE_ACK_PENDING) {
        // Pump the socket to process incoming ACK/NACK without blocking
        (void)doip_receive_data(impl, 0);
        if (!impl->diag_ack_received && !impl->diag_nack_received) {
            status |= UDS_TP_SEND_IN_PROGRESS;
        } else if (impl->diag_nack_received) {
            status |= UDS_TP_ERR;
        } else {
            // ACK received; now expect diagnostic response
            impl->state = DOIP_STATE_DIAG_MESSAGE_RESPONSE_PENDING;
            status |= UDS_TP_SEND_IN_PROGRESS;
        }
        doip_log_poll_state(status, "Ack pending");
        return status;
    }

    // 2) If waiting for diagnostic response, indicate completion when data buffered
    if (impl->state == DOIP_STATE_DIAG_MESSAGE_RESPONSE_PENDING) {
        (void)doip_receive_data(impl, 0);
        if (impl->uds_response_len > 0) {
            status |= UDS_TP_RECV_COMPLETE;
        } else {
            status |= UDS_TP_SEND_IN_PROGRESS; // still waiting on response
        }
        doip_log_poll_state(status, "Response pending");
        return status;
    }

    // 3) Otherwise, if routing is active, we're idle
    if (impl->state == DOIP_STATE_READY_FOR_DIAG_REQUEST) {
        status |= UDS_TP_IDLE;
        doip_log_poll_state(status, "Ready for diag request");
        return status;
    }

    // Any other state is considered an error for transport purposes
    status |= UDS_TP_ERR;
    doip_log_poll_state(status, "Unknown/error state");
    return status;
}

UDSErr_t UDSDoIPInitClient(DoIPClient_t *tp, const char *ipaddress, uint16_t port,
                           uint16_t source_addr, uint16_t target_addr) {
    if (!tp || !ipaddress) {
        return UDS_ERR_INVALID_ARG;
    }

    memset(tp, 0, sizeof(DoIPClient_t));

    tp->socket_fd = -1;
    doip_change_state(tp, DOIP_STATE_DISCONNECTED);
    tp->source_address = source_addr;
    tp->target_address = target_addr;
    strncpy(tp->server_ip, ipaddress, sizeof(tp->server_ip) - 1);
    tp->server_port = port;

    tp->hdl.send = doip_tp_send;
    tp->hdl.recv = doip_tp_recv;
    tp->hdl.poll = doip_tp_poll;

    UDS_LOGI(__FILE__, "UDS DoIP Client: Initialized (SA=0x%04X, TA=0x%04X)", tp->source_address,
             tp->target_address);

    if (doip_client_connect(tp)) {
        UDS_LOGE(__FILE__, "UDS DoIP Client: Connect error");
        return UDS_ERR_TPORT;
    }

    if (doip_client_activate_routing(tp)) {
        UDS_LOGE(__FILE__, "UDS DoIP Client: Routing activation error");
        return UDS_ERR_TPORT;
    }

    return UDS_OK;
}

UDSErr_t UDSDoIPActivateRouting(DoIPClient_t *tp) {
    if (!tp) {
        return UDS_ERR_INVALID_ARG;
    }

    if (doip_client_activate_routing(tp)) {
        UDS_LOGE(__FILE__, "UDS DoIP Client: Routing activation error");
        return UDS_ERR_TPORT;
    }
    return UDS_OK;
}

void UDSDoIPDeinit(DoIPClient_t *tp) {
    if (!tp) {
        return;
    }

    doip_client_disconnect(tp);
}

#endif /* UDS_TP_DOIP */
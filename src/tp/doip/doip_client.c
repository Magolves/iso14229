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


/* DoIP Client Context */
typedef struct {
    int socket_fd;
    DoIPClientState_t state;
    UDSTp_t hdl;

    uint16_t source_address;        /* Client logical address */
    uint16_t target_address;        /* Server logical address */

    char server_ip[64];
    uint16_t server_port;

    uint8_t rx_buffer[DOIP_BUFFER_SIZE];
    size_t rx_offset;

    bool diag_ack_received;
    bool diag_nack_received;
    uint8_t diag_nack_code;

    /* UDS integration callbacks */
    void (*on_diag_response)(uint16_t source_addr, const uint8_t *data, size_t len);
    void *user_data;
} DoIPClient_t;

/* Static client instance */
static DoIPClient_t g_client = {0};

/**
 * @brief Create and initialize DoIP header
 */
static void doip_header_init(DoIPHeader_t *header, uint16_t payload_type, uint32_t payload_length) {
    header->protocol_version = DOIP_PROTOCOL_VERSION;
    header->protocol_version_inv = DOIP_PROTOCOL_VERSION_INV;
    header->payload_type = htons(payload_type);
    header->payload_length = htonl(payload_length);
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
static int doip_send_message(uint16_t payload_type, const uint8_t *payload, uint32_t payload_len) {
    uint8_t buffer[DOIP_BUFFER_SIZE];
    DoIPHeader_t *header = (DoIPHeader_t *)buffer;

    if (DOIP_HEADER_SIZE + payload_len > DOIP_BUFFER_SIZE) {
        return -1;
    }

    doip_header_init(header, payload_type, payload_len);

    if (payload && payload_len > 0) {
        memcpy(buffer + DOIP_HEADER_SIZE, payload, payload_len);
    }

    ssize_t sent = send(g_client.socket_fd, buffer, DOIP_HEADER_SIZE + payload_len, 0);
    if (sent < 0) {
        perror("send");
        return -1;
    }

    return 0;
}

/**
 * @brief Handle routing activation response
 */
static void doip_handle_routing_activation_response(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 9) {
        printf("DoIP: Invalid routing activation response length\n");
        g_client.state = DOIP_STATE_ERROR;
        return;
    }

    uint16_t client_sa = (payload[0] << 8) | payload[1];
    uint16_t server_sa = (payload[2] << 8) | payload[3];
    uint8_t response_code = payload[4];
    (void)client_sa;  /* Validated implicitly by successful response */

    if (response_code == DOIP_ROUTING_ACTIVATION_RES_SUCCESS) {
        g_client.state = DOIP_STATE_ROUTING_ACTIVATED;
        printf("DoIP: Routing activated (SA=0x%04X, TA=0x%04X)\n",
               g_client.source_address, server_sa);
    } else {
        printf("DoIP: Routing activation failed (code=0x%02X)\n", response_code);
        g_client.state = DOIP_STATE_ERROR;
    }
}

/**
 * @brief Handle alive check response
 */
static void doip_handle_alive_check_response(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 2) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    printf("DoIP: Alive check response from 0x%04X\n", source_address);
}

/**
 * @brief Handle diagnostic message positive ACK
 */
static void doip_handle_diag_pos_ack(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 5) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    uint16_t target_address = (payload[2] << 8) | payload[3];
    uint8_t ack_code = payload[4];

    g_client.diag_ack_received = true;

    printf("DoIP: Diagnostic message ACK (SA=0x%04X, TA=0x%04X, code=0x%02X)\n",
           source_address, target_address, ack_code);
}

/**
 * @brief Handle diagnostic message negative ACK
 */
static void doip_handle_diag_neg_ack(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 5) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    uint16_t target_address = (payload[2] << 8) | payload[3];
    uint8_t nack_code = payload[4];

    g_client.diag_nack_received = true;
    g_client.diag_nack_code = nack_code;

    printf("DoIP: Diagnostic message NACK (SA=0x%04X, TA=0x%04X, code=0x%02X)\n",
           source_address, target_address, nack_code);
}

/**
 * @brief Handle diagnostic message (response from server)
 */
static void doip_handle_diag_message(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 4) {
        return;
    }

    uint16_t source_address = (payload[0] << 8) | payload[1];
    uint16_t target_address = (payload[2] << 8) | payload[3];

    /* Verify target address matches our logical address */
    if (target_address != g_client.source_address) {
        printf("DoIP: Received diagnostic message for different TA=0x%04X\n", target_address);
        return;
    }

    /* Pass UDS response data to application callback */
    if (g_client.on_diag_response && payload_len > 4) {
        const uint8_t *uds_data = payload + 4;
        size_t uds_len = payload_len - 4;
        g_client.on_diag_response(source_address, uds_data, uds_len);
    }
}

/**
 * @brief Process received DoIP message
 */
static void doip_process_message(const DoIPHeader_t *header, const uint8_t *payload) {
    switch (header->payload_type) {
        case DOIP_PAYLOAD_TYPE_ROUTING_ACTIVATION_RES:
            doip_handle_routing_activation_response(payload, header->payload_length);
            break;

        case DOIP_PAYLOAD_TYPE_ALIVE_CHECK_RES:
            doip_handle_alive_check_response(payload, header->payload_length);
            break;

        case DOIP_PAYLOAD_TYPE_DIAG_MESSAGE_POS_ACK:
            doip_handle_diag_pos_ack(payload, header->payload_length);
            break;

        case DOIP_PAYLOAD_TYPE_DIAG_MESSAGE_NEG_ACK:
            doip_handle_diag_neg_ack(payload, header->payload_length);
            break;

        case DOIP_PAYLOAD_TYPE_DIAG_MESSAGE:
            doip_handle_diag_message(payload, header->payload_length);
            break;

        default:
            printf("DoIP: Unknown payload type 0x%04X\n", header->payload_type);
            break;
    }
}

/**
 * @brief Receive and process data
 */
static int doip_receive_data(int timeout_ms) {
    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(g_client.socket_fd, &readfds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(g_client.socket_fd + 1, &readfds, NULL, NULL, &tv);
    if (ret < 0) {
        perror("select");
        return -1;
    }

    if (ret == 0) {
        return 0;  /* Timeout */
    }

    ssize_t bytes_read = recv(g_client.socket_fd,
                              g_client.rx_buffer + g_client.rx_offset,
                              DOIP_BUFFER_SIZE - g_client.rx_offset, 0);

    if (bytes_read <= 0) {
        if (bytes_read == 0) {
            printf("DoIP: Server disconnected\n");
        } else {
            perror("recv");
        }
        g_client.state = DOIP_STATE_DISCONNECTED;
        return -1;
    }

    g_client.rx_offset += bytes_read;

    /* Process complete DoIP messages */
    while (g_client.rx_offset >= DOIP_HEADER_SIZE) {
        DoIPHeader_t header;
        if (!doip_header_parse(g_client.rx_buffer, &header)) {
            printf("DoIP: Invalid header\n");
            g_client.state = DOIP_STATE_ERROR;
            return -1;
        }

        size_t total_msg_size = DOIP_HEADER_SIZE + header.payload_length;

        if (g_client.rx_offset < total_msg_size) {
            /* Wait for more data */
            break;
        }

        /* Process message */
        const uint8_t *payload = g_client.rx_buffer + DOIP_HEADER_SIZE;
        doip_process_message(&header, payload);

        /* Remove processed message from buffer */
        if (g_client.rx_offset > total_msg_size) {
            memmove(g_client.rx_buffer,
                   g_client.rx_buffer + total_msg_size,
                   g_client.rx_offset - total_msg_size);
        }
        g_client.rx_offset -= total_msg_size;
    }

    return 1;
}

/**
 * @brief Initialize DoIP client
 */
int doip_client_init(uint16_t source_address,
                     void (*diag_response_callback)(uint16_t, const uint8_t*, size_t)) {
    memset(&g_client, 0, sizeof(DoIPClient_t));

    g_client.socket_fd = -1;
    g_client.state = DOIP_STATE_DISCONNECTED;
    g_client.source_address = source_address;
    g_client.on_diag_response = diag_response_callback;

    printf("DoIP Client: Initialized (SA=0x%04X)\n", source_address);

    return 0;
}

/**
 * @brief Connect to DoIP server
 */
int doip_client_connect(const char *server_ip, uint16_t target_address) {
    if (g_client.state != DOIP_STATE_DISCONNECTED) {
        printf("DoIP: Already connected or in error state\n");
        return -1;
    }

    /* Create TCP socket */
    g_client.socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_client.socket_fd < 0) {
        perror("socket");
        return -1;
    }

    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = DOIP_DEFAULT_TIMEOUT_MS / 1000;
    tv.tv_usec = (DOIP_DEFAULT_TIMEOUT_MS % 1000) * 1000;
    setsockopt(g_client.socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Connect to server */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DOIP_TCP_PORT);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        printf("DoIP: Invalid server IP address\n");
        close(g_client.socket_fd);
        return -1;
    }

    if (connect(g_client.socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(g_client.socket_fd);
        return -1;
    }

    strncpy(g_client.server_ip, server_ip, sizeof(g_client.server_ip) - 1);
    g_client.target_address = target_address;
    g_client.state = DOIP_STATE_CONNECTED;

    printf("DoIP Client: Connected to %s:%d\n", server_ip, DOIP_TCP_PORT);

    return 0;
}

/**
 * @brief Activate routing
 */
int doip_client_activate_routing(void) {
    if (g_client.state != DOIP_STATE_CONNECTED) {
        printf("DoIP: Not connected\n");
        return -1;
    }

    /* Build routing activation request */
    uint8_t payload[11];
    payload[0] = (g_client.source_address >> 8) & 0xFF;
    payload[1] = g_client.source_address & 0xFF;
    payload[2] = DOIP_ROUTING_ACTIVATION_TYPE;
    payload[3] = 0x00;  /* Reserved */
    payload[4] = 0x00;
    payload[5] = 0x00;
    payload[6] = 0x00;

    /* Optional: OEM specific */
    payload[7] = 0x00;
    payload[8] = 0x00;
    payload[9] = 0x00;
    payload[10] = 0x00;

    if (doip_send_message(DOIP_PAYLOAD_TYPE_ROUTING_ACTIVATION_REQ, payload, 11) < 0) {
        return -1;
    }

    g_client.state = DOIP_STATE_ROUTING_ACTIVATION_PENDING;

    /* Wait for routing activation response */
    int timeout_ms = DOIP_DEFAULT_TIMEOUT_MS;
    clock_t start = clock();

    while (g_client.state == DOIP_STATE_ROUTING_ACTIVATION_PENDING) {
        int elapsed_ms = ((clock() - start) * 1000) / CLOCKS_PER_SEC;
        int remaining_ms = timeout_ms - elapsed_ms;

        if (remaining_ms <= 0) {
            printf("DoIP: Routing activation timeout\n");
            g_client.state = DOIP_STATE_ERROR;
            return -1;
        }

        if (doip_receive_data(remaining_ms) < 0) {
            return -1;
        }
    }

    if (g_client.state != DOIP_STATE_ROUTING_ACTIVATED) {
        printf("DoIP: Routing activation failed\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Send diagnostic message
 */
int doip_client_send_diag_message(const uint8_t *data, size_t len) {
    if (g_client.state != DOIP_STATE_ROUTING_ACTIVATED) {
        printf("DoIP: Routing not activated\n");
        return -1;
    }

    /* Build diagnostic message payload */
    uint8_t payload[DOIP_BUFFER_SIZE];
    if (len + 4 > DOIP_BUFFER_SIZE) {
        printf("DoIP: Message too large\n");
        return -1;
    }

    payload[0] = (g_client.source_address >> 8) & 0xFF;
    payload[1] = g_client.source_address & 0xFF;
    payload[2] = (g_client.target_address >> 8) & 0xFF;
    payload[3] = g_client.target_address & 0xFF;
    memcpy(payload + 4, data, len);

    /* Reset ACK/NACK flags */
    g_client.diag_ack_received = false;
    g_client.diag_nack_received = false;

    if (doip_send_message(DOIP_PAYLOAD_TYPE_DIAG_MESSAGE, payload, len + 4) < 0) {
        return -1;
    }

    /* Wait for ACK/NACK */
    int timeout_ms = 1000;  /* 1 second for ACK */
    clock_t start = clock();

    while (!g_client.diag_ack_received && !g_client.diag_nack_received) {
        int elapsed_ms = ((clock() - start) * 1000) / CLOCKS_PER_SEC;
        int remaining_ms = timeout_ms - elapsed_ms;

        if (remaining_ms <= 0) {
            printf("DoIP: Diagnostic message ACK timeout\n");
            return -1;
        }

        if (doip_receive_data(remaining_ms) < 0) {
            return -1;
        }
    }

    if (g_client.diag_nack_received) {
        printf("DoIP: Diagnostic message rejected (NACK code=0x%02X)\n",
               g_client.diag_nack_code);
        return -1;
    }

    return 0;
}

/**
 * @brief Process DoIP client events (call periodically)
 */
void doip_client_process(int timeout_ms) {
    if (g_client.state == DOIP_STATE_ROUTING_ACTIVATED) {
        doip_receive_data(timeout_ms);
    }
}

/**
 * @brief Send alive check request
 */
int doip_client_send_alive_check(void) {
    if (g_client.state != DOIP_STATE_ROUTING_ACTIVATED) {
        printf("DoIP: Not in activated state\n");
        return -1;
    }

    return doip_send_message(DOIP_PAYLOAD_TYPE_ALIVE_CHECK_REQ, NULL, 0);
}

/**
 * @brief Disconnect from DoIP server
 */
void doip_client_disconnect(void) {
    if (g_client.socket_fd >= 0) {
        close(g_client.socket_fd);
        g_client.socket_fd = -1;
    }

    g_client.state = DOIP_STATE_DISCONNECTED;
    g_client.rx_offset = 0;

    printf("DoIP Client: Disconnected\n");
}

/**
 * @brief Get client state
 */
DoIPClientState_t doip_client_get_state(void) {
    return g_client.state;
}

UDSErr_t UDSDoIPInitClient(DoIPClient_t *tp, const char *ipaddress, uint16_t port, uint16_t target_addr);
void UDSDoIPDeinit(DoIPClient_t *tp);

#endif  /* UDS_TP_DOIP */
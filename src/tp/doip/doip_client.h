#if defined(UDS_TP_DOIP)

#pragma once
#include "tp.h"
#include "uds.h"
#include "doip_defines.h"


/* DoIP Client State */
typedef enum {
    DOIP_STATE_DISCONNECTED,
    DOIP_STATE_CONNECTED,
    DOIP_STATE_ROUTING_ACTIVATION_PENDING,
    DOIP_STATE_READY_FOR_DIAG_REQUEST,
    // Diag message states for tracking ACK/NACK and responses
    DOIP_STATE_DIAG_MESSAGE_SEND_PENDING,
    DOIP_STATE_DIAG_MESSAGE_ACK_PENDING,
    DOIP_STATE_DIAG_MESSAGE_RESPONSE_PENDING,
    DOIP_STATE_ERROR
} DoIPClientState_t;

/* DoIP Client Context */
typedef struct {
    UDSTp_t hdl;    /* Must be the first entry! */
    int socket_fd;
    DoIPClientState_t state;

    uint16_t source_address;        /* Client logical address */
    uint16_t target_address;        /* Server logical address */

    char server_ip[64];
    uint16_t server_port;

    uint8_t rx_buffer[DOIP_BUFFER_SIZE];  /* Raw socket receive buffer */
    size_t rx_offset;

    uint8_t uds_response[DOIP_BUFFER_SIZE]; /* Processed UDS response data */
    size_t uds_response_len;

    bool routing_activated;
    bool diag_ack_received;
    bool diag_nack_received;
    uint8_t diag_nack_code;
} DoIPClient_t;


UDSErr_t UDSDoIPInitClient(DoIPClient_t *tp, const char *ipaddress, uint16_t port, uint16_t source_addr, uint16_t target_addr);
void UDSDoIPDeinit(DoIPClient_t *tp);

#endif

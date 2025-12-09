#if defined(UDS_TP_DOIP)

#pragma once
#include "tp.h"
#include "uds.h"


/* DoIP Client State */
typedef enum {
    DOIP_STATE_DISCONNECTED,
    DOIP_STATE_CONNECTED,
    DOIP_STATE_ROUTING_ACTIVATION_PENDING,
    DOIP_STATE_ROUTING_ACTIVATED,
    DOIP_STATE_ERROR
} DoIPClientState_t;

/* DoIP Client Context */
typedef struct {
    int socket_fd;
    DoIPClientState_t state;

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


UDSErr_t UDSDoIPInitClient(DoIPClient_t *tp, const char *ifname, uint32_t source_addr,
                                  uint32_t target_addr, uint32_t target_addr_func);
void UDSDoIPDeinit(DoIPClient_t *tp);

#endif

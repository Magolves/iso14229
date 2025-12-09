#ifndef DOIP_DEFINES_H
#define DOIP_DEFINES_H

#include <stdint.h>

/* DoIP Protocol Constants */
#define DOIP_PROTOCOL_VERSION           0x03
#define DOIP_PROTOCOL_VERSION_INV       0xFC
#define DOIP_TCP_PORT                   13400
#define DOIP_HEADER_SIZE                8

/* DoIP Payload Types */
#define DOIP_PAYLOAD_TYPE_ROUTING_ACTIVATION_REQ    0x0005
#define DOIP_PAYLOAD_TYPE_ROUTING_ACTIVATION_RES    0x0006
#define DOIP_PAYLOAD_TYPE_ALIVE_CHECK_REQ           0x0007
#define DOIP_PAYLOAD_TYPE_ALIVE_CHECK_RES           0x0008
#define DOIP_PAYLOAD_TYPE_DIAG_MESSAGE              0x8001
#define DOIP_PAYLOAD_TYPE_DIAG_MESSAGE_POS_ACK      0x8002
#define DOIP_PAYLOAD_TYPE_DIAG_MESSAGE_NEG_ACK      0x8003

/* DoIP Routing Activation Response Codes */
#define DOIP_ROUTING_ACTIVATION_RES_SUCCESS         0x10
#define DOIP_ROUTING_ACTIVATION_RES_UNKNOWN_SA      0x00
#define DOIP_ROUTING_ACTIVATION_RES_ALREADY_ACTIVE  0x01

/* DoIP Diagnostic Message NACK Codes */
#define DOIP_DIAG_NACK_INVALID_SA                   0x02
#define DOIP_DIAG_NACK_UNKNOWN_TA                   0x03
#define DOIP_DIAG_NACK_MESSAGE_TOO_LARGE            0x04
#define DOIP_DIAG_NACK_OUT_OF_MEMORY                0x05
#define DOIP_DIAG_NACK_TARGET_UNREACHABLE           0x06

/* Configuration */
#define DOIP_MAX_CLIENTS                8
#define DOIP_BUFFER_SIZE                4096
#define DOIP_LOGICAL_ADDRESS_SERVER     0x0001
#define DOIP_ROUTING_ACTIVATION_TYPE    0x00

/* DoIP Header Structure */
typedef struct {
    uint8_t protocol_version;
    uint8_t protocol_version_inv;
    uint16_t payload_type;
    uint32_t payload_length;
} __attribute__((packed)) DoIPHeader_t;



#endif  /* DOIP_DEFINES_H */

/**
 * @file main.c
 * @author Oliver Wieland (oliverwieland@web.de)
 * @brief Example DoIP client using the iso14229 library
 * @version 0.1
 * @date 2025-12-10
 *
 * @copyright Copyright (c) 2025
 *
 */
#include "iso14229.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(UDS_TP_DOIP)

#else
#error "no transport defined"
#endif

UDSErr_t fn(UDSClient_t *client, UDSEvent_t evt, void *ev_data) {
    if (evt != UDS_EVT_Poll) {
        UDS_LOGI(__FILE__, "%s (%d)", UDSEventToStr(evt), evt);
    }
    if (UDS_EVT_Err == evt) {
        UDS_LOGE(__FILE__, "Exiting with error: %s", UDSErrToStr(*(UDSErr_t *)ev_data));
    }
    return UDS_OK;
}

int main(int ac, char **av) {
    UDSClient_t client;
    DoIPClient_t tp;

    UDSErr_t result = UDSDoIPInitClient(&tp, "127.0.0.1", 13400, 0x1234, 0x0001);
    if (result != UDS_OK) {
        UDS_LOGE(__FILE__, "DoIP Client: UDSDoIPInitClient failed with error %d", result);
        UDSDoIPDeinit(&tp);
        exit(-1);
    }

    if (UDSClientInit(&client)) {
        exit(-1);
    }

    client.tp = (UDSTp_t *)&tp;
    client.fn = fn;

    UDS_LOGI(__FILE__, "DoIP Client: UDSDoIPInitClient returned %d", result);

    UDSClientPoll(&client);
    UDSSendRDBI(&client, (uint16_t[]){0xF190, 0xF191}, 2);

    int ms = 100;
    for (int i = 0; i < 100; i++) {
        UDSClientPoll(&client);
        // Simulate a delay of 100 ms between polls
        nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = ms * 1000000}, NULL);
    }

    UDSDoIPDeinit(&tp);
    return EXIT_SUCCESS;
}

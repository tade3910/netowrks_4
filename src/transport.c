/*
 * transport.c 
 *
 * EN.601.414/614: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <arpa/inet.h>

#define MAX_WINDOW_SIZE 3072
#define UNEXPECTED_FLAGS 2
#define EMPTY_READ 1

enum { 
    CSTATE_ESTABLISHED,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLOSING,
    CSTATE_CLOSE_WAIT, // Heavy questions about, how do I wait for application close?
    CSTATE_LAST_ACK,
    CSTATE_TIME_WAIT

};    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num; 
    tcp_seq last_sent_sequence_num;
    tcp_seq last_received_sequence_num;
    //update with gloabal variables

    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

uint16_t get_sending_window(context_t *ctx) {
    return MAX_WINDOW_SIZE - (ntohl(ctx->last_sent_sequence_num) - ntohl(ctx->last_received_sequence_num));
}

void our_dprintf(const char *format,...);

int check_recv(ssize_t received_len, uint8_t received_th_flags,uint8_t expected_th_flags, const char* message) {
    if(received_len < 0 ) {
        printf("No data received when waiting for %s \n", message);
        return EMPTY_READ;
    }
    if(received_th_flags != expected_th_flags) {
        printf("Wrong flag received when waiting for %s \n", message);
        return UNEXPECTED_FLAGS;
    }
    return 0;
}

void clean_up(mysocket_t sd,context_t *ctx) {
    stcp_unblock_application(sd);
    free(ctx);
}

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    fprintf(stdout, "Transport layer initiated\n");
    our_dprintf("Transport layer initiated \n");
    printf("Transport layer initiated\n");
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    our_dprintf("Transport layer initiated \n");
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    if (is_active) { 
        // send syn packet
        STCPHeader *syn_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
        syn_packet->th_flags = TH_SYN;
        syn_packet->th_seq = htonl(ctx->initial_sequence_num);
        syn_packet->th_off = 5;
        syn_packet->th_win = htons(MAX_WINDOW_SIZE);
        stcp_network_send(sd, syn_packet, sizeof(STCPHeader));
        printf("Sent syn packet \n");
        // wait for syn ack
        STCPHeader *received_syn_ack_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        ssize_t received_len = stcp_network_recv(sd, received_syn_ack_packet, sizeof(STCPHeader));
        printf("Received syn ack packet \n");
        // send ack
        STCPHeader *ack_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
        ack_packet->th_flags = TH_ACK;
        ack_packet->th_seq = htonl(ctx->initial_sequence_num + 1);; // ACK the SYN packet
        ack_packet->th_ack = htonl(ntohl(received_syn_ack_packet->th_seq) + 1);
        syn_packet->th_off = 5;
        syn_packet->th_win = htons(MAX_WINDOW_SIZE);
        stcp_network_send(sd, ack_packet, sizeof(STCPHeader));
        printf("Sent ack packet \n");
        ctx->last_received_sequence_num = received_syn_ack_packet->th_seq;
        ctx->last_sent_sequence_num = ack_packet->th_seq;
        free(syn_packet);
        free(received_syn_ack_packet);
        free(ack_packet);
    } else {
        // wait for syn
        STCPHeader *received_syn = (STCPHeader*) malloc(sizeof(STCPHeader));
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        ssize_t received_len = stcp_network_recv(sd, received_syn, sizeof(STCPHeader));
        printf("Received syn packet\n");
        // send syn ack
        STCPHeader *syn_ack_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
        syn_ack_packet->th_flags = TH_SYN | TH_ACK; //Not sure which to set
        syn_ack_packet->th_seq = htonl(ctx->initial_sequence_num); 
        syn_ack_packet->th_ack = htonl(ntohl(received_syn->th_seq) + 1); // ACK the received SYN packet
        syn_ack_packet->th_off = 5;
        syn_ack_packet->th_win = htons(MAX_WINDOW_SIZE);
        stcp_network_send(sd, syn_ack_packet, sizeof(STCPHeader));
        printf("Sent syn ack packet \n");
        // wait for ack
        STCPHeader *received_ack = (STCPHeader*) malloc(sizeof(STCPHeader));
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        received_len = stcp_network_recv(sd, received_ack, sizeof(STCPHeader));
        printf("Received ack packet\n");
        ctx->last_received_sequence_num = received_ack->th_seq;
        ctx->last_sent_sequence_num = syn_ack_packet->th_seq;
        free(received_syn);
        free(syn_ack_packet);
        free(received_ack);
    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    /*ctx->initial_sequence_num =;*/
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            char *buf = (char*) malloc(MAX_WINDOW_SIZE);
            size_t read = stcp_app_recv(sd, buf, MAX_WINDOW_SIZE);
            size_t sent = 0;
            while (sent < read) {
                int to_send = (read - sent) >= STCP_MSS ? STCP_MSS : read - sent;
                stcp_app_send(sd, buf + sent, to_send);
                sent+= to_send;
            }
            free(buf);
        }

        if (event & NETWORK_DATA) {
            /* received data from STCP peer */
            char *buf = (char*) malloc(MAX_WINDOW_SIZE);
            ssize_t received_len = stcp_network_recv(sd, buf, MAX_WINDOW_SIZE);
            STCPHeader* received_segment = (STCPHeader*) buf;
            ctx->last_received_sequence_num = received_segment->th_seq;
            switch (received_segment->th_flags) {
                case TH_FIN: {
                    if(ctx->connection_state == CSTATE_ESTABLISHED) {
                        //ack fin
                        ctx->connection_state = CSTATE_CLOSE_WAIT;
                    } else if(ctx->connection_state == CSTATE_FIN_WAIT_2) {
                        //send ack
                        ctx->connection_state = CSTATE_TIME_WAIT;
                    } else if(ctx->connection_state == CSTATE_FIN_WAIT_1) {
                        //send ack
                        ctx->connection_state = CSTATE_CLOSING;
                    }
                    stcp_fin_received(sd); // let app know no more data is comming so can close
                    break;
                }
                case TH_ACK: {
                    if(ctx->connection_state == CSTATE_FIN_WAIT_1) {
                        // received ack for fin 
                        ctx->connection_state = CSTATE_FIN_WAIT_2; 
                    } else if(ctx->connection_state == CSTATE_LAST_ACK) {
                        //received ack for fin
                        ctx->done = TRUE;
                    } else if(ctx->connection_state == CSTATE_CLOSING) {
                        ctx->connection_state = CSTATE_TIME_WAIT; // how long till timeout?
                    }
                    break;  
                }
                case TH_PUSH: {
                    // Data packet
                }
                default: {
                    break;
                }
            }
            free(buf);
        }

        if (event & APP_CLOSE_REQUESTED) {
            //Initialize four way hand shake
            STCPHeader *fin_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
            fin_packet->th_flags = TH_FIN;
            fin_packet->th_seq = htonl(ntohl(ctx->last_sent_sequence_num) + 1); 
            fin_packet->th_ack = htonl(ntohl(ctx->last_received_sequence_num) + 1); 
            fin_packet->th_off = 5;
            fin_packet->th_win = htons(MAX_WINDOW_SIZE);
            stcp_network_send(sd, fin_packet, sizeof(STCPHeader));
            free(fin_packet);
            switch (ctx->connection_state) {
                case CSTATE_ESTABLISHED:
                    ctx->connection_state = CSTATE_FIN_WAIT_1;
                    break;
                case CSTATE_CLOSE_WAIT:
                    ctx->connection_state = CSTATE_LAST_ACK;
                    break;
                default:
                    printf("This should not happen\n");
                    break;
            }            
        }

        if (event & TIMEOUT) {
            if(ctx->connection_state == CSTATE_TIME_WAIT) ctx->done = TRUE;
            else  printf("This should not happen\n");
        }

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

//Do we deal with the recv and send window in network
// In which packets do we need to set the th_window - just set to max
// I'm a bit confused about close-wait, how do I know to wait for application to be done closing
// Most important thing is I don't know why my print statements are not printing 
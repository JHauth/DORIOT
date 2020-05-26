#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fmt.h"
#include "hashes/sha256.h"
#include "net/gcoap.h"
#include "/home/josh/RIOT/sys/include/od.h"

// #ifdef MODULE_SOCK_DTLS
// #include "net/credman.h"
//
//
// #define SOCK_DTLS_GCOAP_TAG (10)
//
// #ifdef DTLS_PSK
// extern const char psk_key[];
// extern const char psk_id[];
// extern const unsigned psk_key_len;
// extern const unsigned psk_id_len;
// #else /* DTLS_PSK */
// extern const unsigned char ecdsa_priv_key[];
// extern const unsigned char ecdsa_pub_key_x[];
// extern const unsigned char ecdsa_pub_key_y[];
// #endif /* DTLS_ECC */
// #endif /* MODULE_SOCK_DTLS */
//
#define ENABLE_DEBUG (0)
#include "debug.h"

// variables---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
char string[200] = "String that is too long. Like way to long. I don't know whether this will work or not";

#define _LAST_REQ_PATH_MAX (32)
static char _last_req_path[_LAST_REQ_PATH_MAX];

// CoAP resource decalrations----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
static ssize_t _riot_block2_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _string_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _time_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx);

// CoAP resources----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
static const coap_resource_t _resources[] = {
    { "/info", COAP_GET, _riot_block2_handler, NULL },
    { "/string", COAP_GET | COAP_PUT, _string_handler, NULL },
    { "/time", COAP_GET, _time_handler, NULL },
};


// handler functions-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

/* Constants for /riot/ver. */
static const uint8_t block2_intro[] = "This is RIOT (Version: ";
static const uint8_t block2_board[] = " running on a ";
static const uint8_t block2_mcu[] = " board with a ";

static ssize_t _riot_block2_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx) {
    (void)ctx;
    coap_block_slicer_t slicer;
    coap_block2_init(pdu, &slicer);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
    coap_opt_add_block2(pdu, &slicer, 1);
    ssize_t plen = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* Add actual content */
    plen += coap_blockwise_put_bytes(&slicer, buf+plen, block2_intro, sizeof(block2_intro)-1);
    plen += coap_blockwise_put_bytes(&slicer, buf+plen, (uint8_t*)RIOT_VERSION, strlen(RIOT_VERSION));
    plen += coap_blockwise_put_char(&slicer, buf+plen, ')');
    plen += coap_blockwise_put_bytes(&slicer, buf+plen, block2_board, sizeof(block2_board)-1);
    plen += coap_blockwise_put_bytes(&slicer, buf+plen, (uint8_t*)RIOT_BOARD, strlen(RIOT_BOARD));
    plen += coap_blockwise_put_bytes(&slicer, buf+plen, block2_mcu, sizeof(block2_mcu)-1);
    plen += coap_blockwise_put_bytes(&slicer, buf+plen, (uint8_t*)RIOT_MCU, strlen(RIOT_MCU));
    /* To demonstrate individual chars */
    plen += coap_blockwise_put_char(&slicer, buf+plen, ' ');
    plen += coap_blockwise_put_char(&slicer, buf+plen, 'M');
    plen += coap_blockwise_put_char(&slicer, buf+plen, 'C');
    plen += coap_blockwise_put_char(&slicer, buf+plen, 'U');
    plen += coap_blockwise_put_char(&slicer, buf+plen, '.');

    coap_block2_finish(&slicer);

    return plen;
}

static ssize_t _string_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx){

  (void)ctx;

  // get coap method type
  unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));
  char temp[pdu->payload_len/8];
  switch(method_flag){
    case COAP_GET:
      gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
      coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
      size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

      // write to payload
      if (pdu->payload_len >= strlen(string)) {
          memcpy(pdu->payload, string, strlen(string));
          return resp_len + strlen(string);
      } else {
        puts("gcoap_cli: msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
      }
    case COAP_PUT:

      memcpy(temp, (char *)pdu->payload, pdu->payload_len);
      strcpy(string, temp);
      return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
    default:
      return -1;
  }
}

static ssize_t _time_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx){
  (void)ctx;

  time_t currentTime;
  time(&currentTime);
  char time[25];
  strcpy(time, ctime(&currentTime));

  gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
  coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
  size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

  if (pdu->payload_len >= strlen(string)) {
      memcpy(pdu->payload, time, strlen(time));
      return resp_len + strlen(time);
  } else {
    puts("gcoap_cli: msg buffer too small");
    return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
  }
}

// server functions-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
static gcoap_listener_t _listener = {
    &_resources[0],
    sizeof(_resources) / sizeof(_resources[0]),
    NULL,
    NULL
};

void gcoap_cli_init(void){
    gcoap_register_listener(&_listener);
}

static void _resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t* pdu, const sock_udp_ep_t *remote) {
    (void)remote;       /* not interested in the source currently */

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        printf("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        return;
    }
    else if (memo->state == GCOAP_MEMO_ERR) {
        printf("gcoap: error in response\n");
        return;
    }

    coap_block1_t block;
    if (coap_get_block2(pdu, &block) && block.blknum == 0) {
        puts("--- blockwise start ---");
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                            ? "Success" : "Error";
    printf("gcoap: response %s, code %1u.%02u", class_str,
                                                coap_get_code_class(pdu),
                                                coap_get_code_detail(pdu));
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);
        if (content_type == COAP_FORMAT_TEXT
                || content_type == COAP_FORMAT_LINK
                || coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE
                || coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
            /* Expecting diagnostic payload in failure cases */
            printf(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                                                          (char *)pdu->payload);
        }
        else {
            printf(", %u bytes\n", pdu->payload_len);
            //od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
        }
    }
    else {
        printf(", empty payload\n");
    }

    /* ask for next block if present */
    if (coap_get_block2(pdu, &block)) {
        if (block.more) {
            unsigned msg_type = coap_get_type(pdu);
            if (block.blknum == 0 && !strlen(_last_req_path)) {
                puts("Path too long; can't complete blockwise");
                return;
            }

            gcoap_req_init(pdu, (uint8_t *)pdu->hdr, CONFIG_GCOAP_PDU_BUF_SIZE,
                           COAP_METHOD_GET, _last_req_path);
            if (msg_type == COAP_TYPE_ACK) {
                coap_hdr_set_type(pdu->hdr, COAP_TYPE_CON);
            }
            block.blknum++;
            coap_opt_add_block2_control(pdu, &block);
            int len = coap_opt_finish(pdu, COAP_OPT_FINISH_NONE);
            gcoap_req_send((uint8_t *)pdu->hdr, len, remote,
                           _resp_handler, memo->context);
        }
        else {
            puts("--- blockwise complete ---");
        }
    }
}

static size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str) {
    ipv6_addr_t addr;
    size_t bytes_sent;
    sock_udp_ep_t remote;

    remote.family = AF_INET6;

    /* parse for interface */
    char *iface = ipv6_addr_split_iface(addr_str);
    if (!iface) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            remote.netif = SOCK_ADDR_ANY_NETIF;
        }
    }
    else {
        int pid = atoi(iface);
        if (gnrc_netif_get_by_pid(pid) == NULL) {
            puts("gcoap_cli: interface not valid");
            return 0;
        }
        remote.netif = pid;
    }
    /* parse destination address */
    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        puts("gcoap_cli: unable to parse destination address");
        return 0;
    }
    if ((remote.netif == SOCK_ADDR_ANY_NETIF) && ipv6_addr_is_link_local(&addr)) {
        puts("gcoap_cli: must specify interface for link local target");
        return 0;
    }
    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    /* parse port */
    remote.port = atoi(port_str);
    if (remote.port == 0) {
        puts("gcoap_cli: unable to parse destination port");
        return 0;
    }

    bytes_sent = gcoap_req_send(buf, len, &remote, _resp_handler, NULL);
    // if (bytes_sent > 0) {
    //     req_count++;
    // }
    return bytes_sent;
}

// shell functions-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// int gcoap_cli_cmd(int argc, char **argv){
//     if (argc == 1) {
//         /* show help for main commands */
//         goto end;
//     }
//
//     if (strcmp(argv[1], "info") == 0) {
//         uint8_t open_reqs = gcoap_op_state();
//
//         printf("CoAP server is listening on port %u\n", CONFIG_GCOAP_PORT);
//         printf("CoAP open requests: %u\n", open_reqs);
//         return 0;
//     }
//
//     end:
//     printf("usage: %s <info>\n", argv[0]);
//     return 1;
// }


int gcoap_cli_cmd(int argc, char **argv) {
  char *method_codes[] = {"get", "post", "put"};
  uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
  coap_pkt_t pdu;
  size_t len;

  //check if argv is only "coap"
  if (argc == 1) {
      /* show help for main commands */
      goto end;
  }

  if (strcmp(argv[1], "info") == 0) {
      printf("CoAP server is listening on port %u\n", CONFIG_GCOAP_PORT);
      return 0;
  }

  //check for code
  int code_pos = -1;
  for (size_t i = 0; i < ARRAY_SIZE(method_codes); i++) {
      if (strcmp(argv[1], method_codes[i]) == 0) {
          code_pos = i;
      }
  }
  if (code_pos == -1) {
      goto end;
  }



  int apos = 2;               // position of address argument
  unsigned msg_type = COAP_TYPE_NON;
  if (argc > apos && strcmp(argv[apos], "-c") == 0) {
      msg_type = COAP_TYPE_CON;
      apos++;
  }
  //"get" (code_pos 0) must have exactly apos + 3 arguments
  //while "post" (code_pos 1) and "put" (code_pos 2) and must have exactly
  //apos + 4 arguments
  if (((argc == apos + 3) && (code_pos == 0)) ||
      ((argc == apos + 4) && (code_pos != 0))) {
        //initialize message
        gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, code_pos+1, argv[apos+2]);
        //implement -c command
        coap_hdr_set_type(pdu.hdr, msg_type);
        //copy path and store length
        memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
        if (strlen(argv[apos+2]) < _LAST_REQ_PATH_MAX) {
            memcpy(_last_req_path, argv[apos+2], strlen(argv[apos+2]));
        }
        size_t paylen = (argc == apos + 4) ? strlen(argv[apos+3]) : 0;
        //copy path to package and check for max length
        if (paylen) {
            //POST or PUT
            coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
            len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
            //copy path into package
            if (pdu.payload_len >= paylen) {
                memcpy(pdu.payload, argv[apos+3], paylen);
                len += paylen;
            }
            else {
                puts("gcoap_cli: msg buffer too small");
                return 1;
            }
        } else {
            //GET
            len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);
        }

        //send message
        printf("gcoap_cli: sending msg ID %u, %u bytes\n", coap_get_id(&pdu),
               (unsigned) len);
        if (!_send(&buf[0], len, argv[apos], argv[apos+1])) {
            puts("gcoap_cli: msg send failed");
        }
        else {
          printf("Sending request\n" );
            /* send Observe notification for /cli/stats */
            // switch (gcoap_obs_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE,
            //         &_resources[0])) {
            // case GCOAP_OBS_INIT_OK:
            //     DEBUG("gcoap_cli: creating /cli/stats notification\n");
            //     coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
            //     len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
            //     len += fmt_u16_dec((char *)pdu.payload, req_count);
            //     gcoap_obs_send(&buf[0], len, &_resources[0]);
            //     break;
            // case GCOAP_OBS_INIT_UNUSED:
            //     DEBUG("gcoap_cli: no observer for /cli/stats\n");
            //     break;
            // case GCOAP_OBS_INIT_ERR:
            //     DEBUG("gcoap_cli: error initializing /cli/stats notification\n");
            //     break;
            // }
        }
        return 0;
      } else {
          //error?
          printf("usage: %s <get|post|put> [-c] <addr>[%%iface] <port> <path> [data]\n",
                 argv[0]);
          printf("Options\n");
          printf("    -c  Send confirmably (defaults to non-confirmable)\n");
          return 1;
      }

  end:
  printf("usage: %s <get|post|put|info>\n", argv[0]);
  return 1;

}

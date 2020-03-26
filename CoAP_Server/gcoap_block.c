#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fmt.h"
#include "hashes/sha256.h"
#include "net/gcoap.h"
#include "kernel_types.h"


// variables---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
char string[200] = "String that is too long. Like way to long. I don't know whether this will work or not";

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
// shell functions-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int gcoap_cli_cmd(int argc, char **argv){
    if (argc == 1) {
        /* show help for main commands */
        goto end;
    }

    if (strcmp(argv[1], "info") == 0) {
        uint8_t open_reqs = gcoap_op_state();

        printf("CoAP server is listening on port %u\n", CONFIG_GCOAP_PORT);
        printf("CoAP open requests: %u\n", open_reqs);
        return 0;
    }

    end:
    printf("usage: %s <info>\n", argv[0]);
    return 1;
}

int threadcounter(int argc, char **argv){
  if(argc<2){
    int n = 0;
    for (kernel_pid_t i = KERNEL_PID_FIRST; i <= KERNEL_PID_LAST; i++){
      n++;
    }
    printf("Number or running threads is: %d\n", n);
  } else {
    printf("%s is not a valid input\n", argv[0]);
  }
  return 0;
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

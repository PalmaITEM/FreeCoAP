/*
 * Copyright (c) 2015 Keith Cullen.
 * All Rights Reserved.
 *
 * (from test_coap_server.c)
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 * Copyright (c) 2017 David Palma.
 * All Rights Reserved.
 * 
 * (modifications and additions to test_coap_server.c)
 * 
 * This software is released free of charge as open source software with a GNU 
 * General Public License.
 * It is free software: you can redistribute it and/or modify it under the 
 * terms of the GNU General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
 * more details.
 * 
 */

/**
 *  @file mr_server.c
 *
 *  @brief FreeCoAP server application that answers CoAP requests 
 *  by requesting resources directly from an HTTP server
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "coap_server.h"
#include "coap_log.h"
#include <getopt.h>
#include "http_to_mem.h"

#include <unistd.h>

#ifdef COAP_IP6
#define HOST                 "::"                                               /**< Host address to listen on */
#else
#define HOST                 "0.0.0.0"                                          /**< Host address to listen on */
#endif
//#define PORT                 "12436"                                            /**< UDP port number to listen on */
#define PORT                 "61617"                                            /**< UDP port number to listen on */
#define KEY_FILE_NAME        "../../certs/server_privkey.pem"                   /**< DTLS key file name */
#define CERT_FILE_NAME       "../../certs/server_cert.pem"                      /**< DTLS certificate file name */
#define TRUST_FILE_NAME      "../../certs/root_client_cert.pem"                 /**< DTLS trust file name */
#define CRL_FILE_NAME        ""                                                 /**< DTLS certificate revocation list file name */
#define BLOCKWISE_BUF_LEN    132000                                                 /**< Total length (in bytes) of the buffer used for blockwise transfers */
#ifndef BLOCK_SIZE
    #define BLOCK_SIZE      16                                                 /**< Size of an individual block in a blockwise transfer MUST BE POWER OF 2 */
#endif

/**
 *  @brief Print a CoAP message
 *
 *  @param[in] str String to be printed before the message
 *  @param[in] msg Pointer to a message structure
 */
static void print_coap_msg(const char *str, coap_msg_t *msg)
{
    coap_log_level_t log_level = 0;
    coap_msg_op_t *op = NULL;
    unsigned num = 0;
    unsigned len = 0;
    unsigned i = 0;
    unsigned j = 0;
//    char *payload = NULL;
    char *token = NULL;
    char *val = NULL;

    log_level = coap_log_get_level();
    if (log_level < COAP_LOG_INFO)
    {
        return;
    }
    printf("%s\n", str);
    printf("ver:         0x%02x\n", coap_msg_get_ver(msg));
    printf("type:        0x%02x\n", coap_msg_get_type(msg));
    printf("token_len:   %d\n", coap_msg_get_token_len(msg));
    printf("code_class:  %d\n", coap_msg_get_code_class(msg));
    printf("code_detail: %d\n", coap_msg_get_code_detail(msg));
    printf("msg_id:      0x%04x\n", coap_msg_get_msg_id(msg));
    printf("token:      ");
    token = coap_msg_get_token(msg);
    for (i = 0; i < coap_msg_get_token_len(msg); i++)
    {
        printf(" 0x%02x", (unsigned char)token[i]);
    }
    printf("\n");
    op = coap_msg_get_first_op(msg);
    while (op != NULL)
    {
        num = coap_msg_op_get_num(op);
        len = coap_msg_op_get_len(op);
        val = coap_msg_op_get_val(op);
        printf("op[%u].num:   %u\n", j, num);
        printf("op[%u].len:   %u\n", j, len);
        printf("op[%u].val:  ", j);
        for (i = 0; i < len; i++)
        {
            printf(" 0x%02x", (unsigned char)val[i]);
        }
        printf("\n");
        op = coap_msg_op_get_next(op);
        j++;
    }
/* Too much for websites
    printf("payload:     ");
    payload = coap_msg_get_payload(msg);
    for (i = 0; i < coap_msg_get_payload_len(msg); i++)
    {
        printf("%c", payload[i]);
    }
    printf("\n");
*/
    printf("payload_len: %zu\n", coap_msg_get_payload_len(msg));
    fflush(stdout);
}

/**
 *  @brief Find and parse a Block1 or Block2 option
 *
 *  @param[out] num Pointer to Block number
 *  @param[out] more Pointer to More value
 *  @param[out] size Pointre to Block size (in bytes)
 *  @param[in] msg Pointer to a CoAP message
 *  @param[in] type Block option type: COAP_MSG_BLOCK1 or COAP_MSG_BLOCK2
 *
 *  @returns Operation status
 *  @retval 1 Block option not found
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_parse_block_op(unsigned *num, unsigned *more, unsigned *size, coap_msg_t *msg, int type)
{
    coap_msg_op_t *op = NULL;
    unsigned op_num = 0;
    unsigned op_len = 0;
    char *op_val = NULL;

    op = coap_msg_get_first_op(msg);
    while (op != NULL)
    {
        op_num = coap_msg_op_get_num(op);
        op_len = coap_msg_op_get_len(op);
        op_val = coap_msg_op_get_val(op);
        if (((op_num == COAP_MSG_BLOCK1) && (type == COAP_MSG_BLOCK1))
         || ((op_num == COAP_MSG_BLOCK2) && (type == COAP_MSG_BLOCK2)))
        {
            return coap_msg_op_parse_block_val(num, more, size, op_val, op_len);
        }
        op = coap_msg_op_get_next(op);
    }
    return 1;  /* not found */
}

//static char blockwise_buf[BLOCKWISE_BUF_LEN] = {0};                             /**< Buffer used for blockwise transfers */
char *blockwise_buf; //[BLOCKWISE_BUF_LEN];                             /**< Buffer used for blockwise transfers */
long blockwise_buf_len;

/**
 *  @brief Handle blockwise transfers
 *
 *  This function handles requests and responses that
 *  involve blockwise transfers.
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle_blockwise(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    const char *payload = NULL;
    unsigned code_detail = 0;
    unsigned code_class = 0;
    unsigned block_size = 0;
    unsigned block_more = 0;
    unsigned block_num = 0;
    unsigned start = 0;
    unsigned len = 0;
    int ret = 0;

    coap_msg_op_t *op = NULL;
    char full_uri[2048]; //the HTTP standard defines a max size of 2000
    char *uri_start;
    char *uri_val = NULL;
    size_t uri_len = 0;
    int uri_num = 0;
    char *block_val = NULL;
    int block_len = 0;

    /* determine method */
    code_class = coap_msg_get_code_class(req);
    code_detail = coap_msg_get_code_detail(req);
    if (code_class != COAP_MSG_REQ)
    {
        coap_log_warn("Received request message with invalid code class: %d", code_class);
        return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
    }
    if (code_detail == COAP_MSG_PUT)
    {
        /* request */
        ret = server_parse_block_op(&block_num, &block_more, &block_size, req, COAP_MSG_BLOCK1);
        if (ret < 0)
        {
            coap_log_warn("Unable to parse Block1 option value in request message");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
        }
        if (ret == 1)
        {
            /* no Block1 option in the request */
            coap_log_warn("Received request message without Block1 option");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        start = block_num * block_size;

        if (start >= sizeof(blockwise_buf))
        {
            coap_log_warn("Received request message with invalid Block1 option value");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        len = coap_msg_get_payload_len(req);
        if (start + len > sizeof(blockwise_buf))
        {
            len = sizeof(blockwise_buf) - start;
        }
        payload = coap_msg_get_payload(req);
        if (payload == NULL)
        {
            coap_log_warn("Received request message without payload");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        memcpy(blockwise_buf + start, payload, len);

        /* response */

        /* 
         * determine the size of block val. depending on block num.
         * this avoids unnecessary overhead (maximum is 3 bytes)
         * https://tools.ietf.org/html/rfc7959#section-2.2
         */
        if(block_num < 16)
            block_len = 1;
        else if (block_num < 4096)
            block_len = 2;
        else
            block_len=3;
        block_val = (char *) malloc(block_len);      
        
        ret = coap_msg_op_format_block_val(block_val, block_len, block_num, 0, block_size);
        if (ret < 0)
        {
            coap_log_error("Failed to format Block1 option value, num:%d, size:%d", block_num, block_size);
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        ret = coap_msg_add_op(resp, COAP_MSG_BLOCK1, ret, block_val);
        //Free val because it has been copied
        free(block_val);
        if (ret < 0)
        {
            coap_log_error("Failed to add Block1 option to response message");
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CHANGED);
    }
    else if (code_detail == COAP_MSG_GET)
    {
        /* request */
        ret = server_parse_block_op(&block_num, &block_more, &block_size, req, COAP_MSG_BLOCK2);
        if (ret < 0)
        {
            coap_log_warn("Unable to parse Block2 option value in request message");
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_OPTION);
        }
        if (ret == 1)
        {
            /* no Block2 option in the request */
            coap_log_info("No Block2 in request\n");
            block_size = BLOCK_SIZE;
        }

        if(block_num == 0){
            /* Open Webpage for first request only! */

            op = coap_msg_get_first_op(req);
            uri_start = full_uri;
            uri_len = 0;
            while (op != NULL)
            {
                uri_num = coap_msg_op_get_num(op);
                if (uri_num == COAP_MSG_URI_PATH)
                {
                    uri_val = coap_msg_op_get_val(op);
                    uri_len = coap_msg_op_get_len(op);
                    //Keep track and avoid buffer overruns
                    if ((uri_start - full_uri)+uri_len < 2040) { // extra room for "//"
                        memcpy(uri_start, uri_val, uri_len);
                    }
                    uri_start += uri_len;

                    //checking first uri ONLY for http(s) or file
                    if ( uri_start - full_uri - uri_len == 0) {
                        //for string comparison
                        *uri_start = '\0';
                        if ( strcmp(full_uri, "http:") == 0 || strcmp(full_uri, "https:") == 0 ) {
                            //Adding extra slash to cover http and https in address
                            *uri_start = '/';
                            *(uri_start+1) = '/';
                            uri_start+=2;
                        } else if ( strcmp(full_uri, "file:") == 0 ) {
                            //Adding extra slashes to cover file in address
                            *uri_start = '/';
                            *(uri_start+1) = '/';
                            *(uri_start+2) = '/';
                            uri_start+=3;
                        }
                    }
                    //Add URI's slash '/'
                    if (*(uri_start-1) != '/') {
                        *uri_start = '/';
                        uri_start++;
                    }
                }
                op = coap_msg_op_get_next(op);
            }
            //end string and remove the final slash
            uri_start--;
            *uri_start = '\0';
            coap_log_debug("The full URI for HTML req: %s", full_uri);

            //Getting HTTP data
            blockwise_buf_len = http_to_mem(full_uri);
            if ( blockwise_buf_len <= 0)
            {
                coap_log_error("Failed to get payload from HTTP server");
                return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
            }
            coap_log_debug("Got HTML Size: %ld\n", blockwise_buf_len);
            blockwise_buf = get_http_mem();

        }

        start = block_num * block_size;
        if (start >= blockwise_buf_len ) 
        {
            coap_log_warn("Received request message with invalid Block2 option value");
            http_to_mem_cleanup();
            blockwise_buf_len = 0;
            blockwise_buf = NULL;
            return coap_msg_set_code(resp, COAP_MSG_CLIENT_ERR, COAP_MSG_BAD_REQ);
        }
        len = block_size;
        block_more = 1;
        if (start + len >= blockwise_buf_len ) 
        {
            block_more = 0;
            len = blockwise_buf_len - start;  
        }

        /* response */
        coap_log_debug("Preparing response: %u, %u, %u", block_num, block_more, block_size);

        /* 
         * determine the size of block val. depending on block num.
         * this avoids unnecessary overhead (maximum is 3 bytes)
         * https://tools.ietf.org/html/rfc7959#section-2.2
         */
        if(block_num < 16)
            block_len = 1;
        else if (block_num < 4096)
            block_len = 2;
        else
            block_len=3;
        block_val = (char *) malloc(block_len);

        ret = coap_msg_op_format_block_val(block_val, block_len, block_num, block_more, block_size);
        if (ret < 0)
        {
            coap_log_error("Failed to format Block2 option value");
            http_to_mem_cleanup();
            blockwise_buf_len = 0;
            blockwise_buf = NULL;
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        ret = coap_msg_add_op(resp, COAP_MSG_BLOCK2, ret, block_val);
        //Free val because it has been copied
        free(block_val);
        if (ret < 0)
        {
            coap_log_error("Failed to add Block2 option to response message");
            http_to_mem_cleanup();
            blockwise_buf_len = 0;
            blockwise_buf = NULL;
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }
        ret = coap_msg_set_payload(resp, blockwise_buf + start, len);
        if (ret < 0)
        {
            coap_log_error("Failed to add payload to response message");
            http_to_mem_cleanup();
            blockwise_buf_len = 0;
            blockwise_buf = NULL;
            return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_INT_SERVER_ERR);
        }

        /* Success */
        if (block_more == 0)
        {
            //coap_msg_set_payload copies the payload, and this is the last block, so we can free resources
            http_to_mem_cleanup();
            blockwise_buf_len = 0;
            blockwise_buf = NULL;
        }
        return coap_msg_set_code(resp, COAP_MSG_SUCCESS, COAP_MSG_CONTENT);
    }
    coap_log_warn("Received request message with unsupported code detail: %d", code_detail);
    return coap_msg_set_code(resp, COAP_MSG_SERVER_ERR, COAP_MSG_NOT_IMPL);
}


/**
 *  @brief Callback function to handle requests and generate responses
 *
 *  The handler function is called to service a request
 *  and produce a response. This function should only set
 *  the code and payload fields in the response message.
 *  The other fields are set by the server library when
 *  this function returns.
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int server_handle(coap_server_t *server, coap_msg_t *req, coap_msg_t *resp)
{
    int ret = 0;

    ret = server_handle_blockwise(server, req, resp);
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        return ret;
    }
    print_coap_msg("Received:", req);
    print_coap_msg("Sent: (Note: the type, message ID and token fields have not been set by the server library yet)", resp);
    return 0;
}

/**
 *  @brief Helper function to list command line options
 */
static void usage(void)
{
    printf("usage: mr_server [options]\n");
    printf("options:\n");
    printf("    -h help\n");
    printf("    -v VERBOSITY_LEVEL verbose\n");
}

/**
 *  @brief Main function for the CoAP server test application
 *
 *  @returns Operation status
 *  @retval EXIT_SUCCESS Success
 *  @retval EXIT_FAILURE Error
 */
int main(int argc, char **argv)
{
    const struct option long_opts[] =
    {
        {"help",    no_argument,       NULL, 'h'},
        {"verbosity",  required_argument, NULL, 'v'},
        {0, 0, 0, 0}
    };
    const char *short_opts = ":hv:";
    int c, long_index, verbosity = COAP_LOG_ERROR;

    coap_server_t server = {0};
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    /* disable getopt() error messages */
    opterr = 0;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, &long_index)) != -1)
    {
        switch (c)
        {
        case 'h' :
            usage();
            return EXIT_SUCCESS;
            break;
        case 'v' :
            verbosity = atoi(optarg);
            if (verbosity > COAP_LOG_DEBUG)
                verbosity = COAP_LOG_DEBUG;
            else if (verbosity < COAP_LOG_ERROR)
                verbosity = COAP_LOG_ERROR;

            break;
        case ':' :  /* missing operand */
            if ((argv[optind - 1][0] == '-') && (argv[optind - 1][1] == '-'))
                fprintf(stderr, "Error: option '%s' requires an argument\n", argv[optind - 1] + 2);
            else
                fprintf(stderr, "Error: option '%c' requires an argument\n", optopt);
            return EXIT_FAILURE;
            break;
        case '?' :
            if ((argv[optind - 1][0] == '-') && (argv[optind - 1][1] == '-'))
                fprintf(stderr, "Error: unknown option '%s'\n", argv[optind - 1] + 2);
            else
                fprintf(stderr, "Error: unknown option '%c'\n", optopt);
            return EXIT_FAILURE;
            break;
        default :
            usage();
            return EXIT_FAILURE;
        }
    }
    if (optind < argc)
    {
        fprintf(stderr, "Error: unknown option '%s'\n", argv[optind]);
        return EXIT_FAILURE;
    }

    coap_log_set_level(verbosity); //NOTICE

#ifdef COAP_DTLS_EN
    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        return EXIT_FAILURE;
    }
    coap_log_info("GnuTLS version: %s", gnutls_ver);

    ret = coap_server_create(&server, server_handle, HOST, PORT, KEY_FILE_NAME, CERT_FILE_NAME, TRUST_FILE_NAME, CRL_FILE_NAME);
#else
    ret = coap_server_create(&server, server_handle, HOST, PORT);
#endif
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        return EXIT_FAILURE;
    }

    ret = coap_server_run(&server);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        coap_server_destroy(&server);
        return EXIT_FAILURE;
    }
    coap_server_destroy(&server);
    return EXIT_SUCCESS;
}

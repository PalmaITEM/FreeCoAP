/*
 * Copyright (c) 2008 Keith Cullen.
 * All Rights Reserved.
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
 * 
 * Copyright (c) 2017 David Palma.
 * All Rights Reserved.
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
 *  @file connection.h
 *
 *  @brief Include file for the FreeCoAP HTTP/CoAP proxy conection module
 */

#ifndef CONNECTION_H
#define CONNECTION_H

#include <netinet/in.h>
#include "coap_client.h"
#include "tls_sock.h"
#include "data_buf.h"
#include "param.h"
#include <stdbool.h>

typedef struct
{
    unsigned listener_index;
    unsigned con_index;
    unsigned num_exchanges;
    char addr[SOCK_INET_ADDRSTRLEN];
    tls_sock_t *sock;
    data_buf_t recv_buf;
    data_buf_t send_buf;
    param_t *param;
    int coap_client_active;
    char *coap_client_host;
    char *coap_client_port;
    coap_client_t coap_client;
}
connection_t;

int connection_init(void);
void *connection_thread_func(void *data);
connection_t *connection_new(tls_sock_t *sock, unsigned listener_index, unsigned con_index, param_t *param);
void connection_delete(connection_t *con);

bool proxy_handle_blockwise_op(coap_msg_t *resp, coap_msg_t *req, unsigned *block_num, unsigned *block_size);
int proxy_parse_block_op(unsigned *num, unsigned *more, unsigned *size, coap_msg_t *msg, int type);
int proxy_add_or_replace_block_op_val(coap_msg_t *msg, unsigned op_block_len, char* block_val, int type);

#endif

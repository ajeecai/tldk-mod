/*
 * Copyright (c) 2017  Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __TLDK_SOCK_H__
#define __TLDK_SOCK_H__

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include <tle_ip.h>
#include <tle_tcp.h>

struct tle_dev;

/*** init_func_hook must be in first place ***/
void init_func_hook(void);

struct rte_mempool *tle_init_pkt_pool(int pkt_num);
struct tle_dev *tle_init_dev(struct tle_dev_param *prm);
void tle_init_streams(void);

void tle_engine(void);
void tle_input(struct rte_mbuf *pkt[], int num);
int socket(int domain, int type, int protocol);
int bind(int sd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sd, int backlog);
int accept(int sd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t read(int sd, void *buf, size_t len);
ssize_t write(int sd, const void *buf, size_t len);
int close(int sd);

#endif /* __TLDK_SOCK_H__ */

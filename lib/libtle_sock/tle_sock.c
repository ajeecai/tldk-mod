/*
 * Copyright (c) 2016-2017  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <time.h>
#include <dlfcn.h>
#include "netbe.h"
#include "parse.h"
#include "tle_ip.h"
#include "tle_sock.h"

#define MAX_RULES 0x100
#define MAX_TBL8 0x800

#define RX_RING_SIZE 0x400
#define TX_RING_SIZE 0x800

#define MPOOL_CACHE_SIZE 0x100
#define MPOOL_NB_BUF 0x20000
#define TLE_MAX_STREAMS 1000
#define TLE_MAX_MBUFS 0x100
#define TLE_MAX_BACKLOG 10

#define FRAG_MBUF_BUF_SIZE (RTE_PKTMBUF_HEADROOM + TLE_DST_MAX_HDR)
#define FRAG_TTL MS_PER_S
#define FRAG_TBL_BUCKET_ENTRIES 16

#define FIRST_PORT 0x8000

#define RX_CSUM_OFFLOAD (RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
#define TX_CSUM_OFFLOAD (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM)

#define INIT_FUNC(func)                        \
	do                                         \
	{                                          \
		real_##func = dlsym(RTLD_NEXT, #func); \
		RTE_ASSERT(real_##func);               \
	} while (0)

#define CORE_NUM_SHIFT_BITS __builtin_clz(RTE_MAX_LCORE)
#define MASK_OUT_CORE_NUM ((1 << CORE_NUM_SHIFT_BITS) - 1)

#define STREAM_TO_FD(stream, lcore) (int)(((char *)stream - (char *)RTE_PER_LCORE(tldk_ctx)->fs) / \
											  sizeof(struct netfe_stream) +                        \
										  ((lcore + 1) << CORE_NUM_SHIFT_BITS))
#define FD_TO_STREAM(fd) (struct netfe_stream *)((fd & MASK_OUT_CORE_NUM) * sizeof(struct netfe_stream) + \
												 (char *)RTE_PER_LCORE(tldk_ctx)->fs)
#define IS_VALID_TLE_FD(fd) (fd & (~CORE_NUM_SHIFT_BITS))

RTE_DEFINE_PER_LCORE(struct netbe_lcore *, _be);
RTE_DEFINE_PER_LCORE(struct netfe_lcore *, _fe);

#include "fwdtbl.h"

/**
 * Location to be modified to create the IPv4 hash key which helps
 * to distribute packets based on the destination TCP/UDP port.
 */
#define RSS_HASH_KEY_DEST_PORT_LOC_IPV4 15

/**
 * Location to be modified to create the IPv6 hash key which helps
 * to distribute packets based on the destination TCP/UDP port.
 */
#define RSS_HASH_KEY_DEST_PORT_LOC_IPV6 39

/**
 * Size of the rte_eth_rss_reta_entry64 array to update through
 * rte_eth_dev_rss_reta_update.
 */
#define RSS_RETA_CONF_ARRAY_SIZE (RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE)

// static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
// static int (*real_close)(int);
// static ssize_t (*real_readv)(int, const struct iovec *, int);
// static ssize_t (*real_recv)(int, void *, size_t, int);
// static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
// static int (*real_shutdown)(int, int);
// static ssize_t (*real_writev)(int, const struct iovec *, int);
static int (*real_socket)(int domain, int type, int protocol);
static int (*real_bind)(int sd, const struct sockaddr *addr,
						socklen_t addrlen);
static int (*real_accept)(int sd, struct sockaddr *addr,
						  socklen_t *addrlen);
static int (*real_listen)(int sd, int backlog);
static ssize_t (*real_read)(int fd, void *buf, size_t count);
static ssize_t (*real_write)(int fd, const void *buf, size_t count);
static int (*real_connect)(int sd, const struct sockaddr *addr, socklen_t addrlen);
static int (*real_close)(int fd);

static struct netbe_cfg becfg = {.mpool_buf_num = MPOOL_NB_BUF};
static struct rte_mempool *mpool[RTE_MAX_NUMA_NODES + 1];
static struct rte_mempool *frag_mpool[RTE_MAX_NUMA_NODES + 1];
static char proto_name[3][10] = {"udp", "tcp", ""};

static struct lcore_prm g_prm[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf_default;

struct tx_content tx_content = {
	.sz = 0,
	.data = NULL,
};

static int inited = 0;

int verbose = VERBOSE_NONE;
struct tldk_ctx
{
	struct tle_ctx *ctx;
	struct tle_dev *dev;
	struct rte_mempool *mp;
	// struct rte_mempool *frag_mp;

	struct tle_evq *syneq;
	struct tle_evq *ereq;
	struct tle_evq *rxeq;
	struct tle_evq *txeq;
	struct
	{
		uint64_t acc;
		uint64_t rej;
		uint64_t ter;
	} tcp_stat;
	struct netfe_stream *fs;
	struct netfe_stream_list free;
	struct netfe_stream_list use;
};

#include "common.h"
#include "parse.h"
#include "lcore.h"
#include "port.h"
#include "tcp.h"
#include "udp.h"

RTE_DEFINE_PER_LCORE(struct tldk_ctx *, tldk_ctx);

struct rte_mempool *tle_init_pkt_pool(int pkt_num)
{
	int32_t rc = 0;
	uint32_t lcore_id = rte_lcore_id();
	int sid = rte_lcore_to_socket_id(lcore_id);
	// struct rte_mempool *mp, *frag_mp;
	struct rte_mempool *mp;
	char name[RTE_MEMPOOL_NAMESIZE];

	if (pkt_num <= 100)
	{
		pkt_num = MPOOL_NB_BUF;
	}
	snprintf(name, sizeof(name), "RX-MP%u", sid);
	mp = rte_pktmbuf_pool_create(
		name, pkt_num, MPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, sid);
	if (mp == NULL)
	{
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s(%d) failed with error code: %d\n", __func__, sid, rc);
		return NULL;
	}

	// snprintf(name, sizeof(name), "frag_MP%u", sid);
	// frag_mp = rte_pktmbuf_pool_create(
	// 	name, MPOOL_NB_BUF, MPOOL_CACHE_SIZE, 0, FRAG_MBUF_BUF_SIZE, sid);
	// if (frag_mp == NULL)
	// {
	// 	rc = -rte_errno;
	// 	RTE_LOG(ERR, USER1, "%s(%d) failed with error code: %d\n", __func__, sid - 1, rc);
	// 	return rc;
	// }
	// RTE_PER_LCORE(tldk_ctx)->frag_mp = frag_mp;

	return mp;
}

static int lookup4(void *p, const struct in_addr *addr, struct tle_dest *res)
{
	int rc = 0;
	struct rte_mempool *mp = (struct rte_mempool *)p;
	memset(res, 0, sizeof(struct tle_dest));

	rc = search_best_match_route(mp, addr->s_addr, res);

	RTE_LOG(ERR, USER1, "%s: return dest, rc %d\n", __func__, rc);
	return rc;
}
static int lookup6(void *opaque, const struct in6_addr *addr, struct tle_dest *res)
{
	(void)opaque;
	(void)addr;
	(void)res;
	RTE_LOG(ERR, USER1, "%s: null\n", __func__);
	return 0;
}
static struct tle_ctx *tle_init_ctx(struct rte_mempool *mp)
{
	int lcore_id = rte_lcore_id();
	struct tle_ctx_param cprm;
	struct tle_ctx *ctx;
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);

	memset(&cprm, 0, sizeof(struct tle_ctx_param));

	cprm.socket_id = rte_lcore_to_socket_id(lcore_id);
	cprm.proto = TLE_PROTO_TCP;
	cprm.max_streams = TLE_MAX_STREAMS;
	cprm.max_stream_rbufs = cprm.max_stream_sbufs = TLE_MAX_MBUFS;
	cprm.send_bulk_size = 1;
	cprm.lookup4 = lookup4;
	cprm.lookup4_data = mp;
	cprm.lookup6 = lookup6;
	cprm.lookup6_data = NULL;
	cprm.hash_alg = TLE_JHASH;
	cprm.secret_key.u64[0] = rte_rand();
	cprm.secret_key.u64[1] = rte_rand();
	// cprm.icw = 0
	cprm.timewait = TLE_TCP_TIMEWAIT_DEFAULT;

	tldk_ctx = rte_zmalloc_socket(NULL, sizeof(struct tldk_ctx), RTE_CACHE_LINE_SIZE,
								  cprm.socket_id);

	if (!tldk_ctx)
	{
		RTE_LOG(ERR, USER1, "%s %d: can't allocate tldk_ctx memory\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	tldk_ctx->mp = mp;
	RTE_PER_LCORE(tldk_ctx) = tldk_ctx;
	ctx = tle_ctx_create(&cprm);
	RTE_PER_LCORE(tldk_ctx)->ctx = ctx;

	return ctx;
}

struct tle_dev *tle_init_dev(struct tle_dev_param *prm)
{
	struct tle_ctx *ctx = tle_init_ctx(prm->mp);
	if (!ctx)
	{
		RTE_LOG(ERR, USER1, "%s %d: tle_add_dev return NULL\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}
	struct tle_dev *dev = tle_add_dev(ctx, prm);
	if (!dev)
	{
		RTE_LOG(ERR, USER1, "%s %d: tle_add_dev return NULL\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	// RTE_PER_LCORE(dev) = dev;
	RTE_PER_LCORE(tldk_ctx)->dev = dev;

	return dev;
}
void tle_init_streams(void)
{
	int i, sz;
	int lcore_id = rte_lcore_id();
	struct tle_evq_param eprm;
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);

	// RTE_PER_LCORE(free) = &tldk_ctx->free;
	// RTE_PER_LCORE(use) = &tldk_ctx->use;

	memset(&eprm, 0, sizeof(eprm));
	eprm.socket_id = rte_lcore_to_socket_id(lcore_id);
	eprm.max_events = TLE_MAX_STREAMS;

	tldk_ctx->syneq = tle_evq_create(&eprm);
	tldk_ctx->ereq = tle_evq_create(&eprm);
	tldk_ctx->rxeq = tle_evq_create(&eprm);
	tldk_ctx->txeq = tle_evq_create(&eprm);

	sz = TLE_MAX_STREAMS * sizeof(struct netfe_stream);
	tldk_ctx->fs = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
									  eprm.socket_id);
	if (!tldk_ctx->fs)
	{
		RTE_LOG(ERR, USER1, "%s: can't allocate %d memory\n", __func__, sz);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < TLE_MAX_STREAMS; i++)
	{
		tldk_ctx->fs[i].rxev = tle_event_alloc(tldk_ctx->rxeq, tldk_ctx->fs + i);
		tldk_ctx->fs[i].txev = tle_event_alloc(tldk_ctx->txeq, tldk_ctx->fs + i);
		tldk_ctx->fs[i].erev = tle_event_alloc(tldk_ctx->ereq, tldk_ctx->fs + i);
		netfe_put_stream(&tldk_ctx->free, tldk_ctx->fs + i);
	}
	inited = 1;
}

/***************** socket API *****************/

/* this hook must be at the very beginning of main*/
void init_func_hook(void)
{
	INIT_FUNC(socket);
	INIT_FUNC(bind);
	INIT_FUNC(listen);
	INIT_FUNC(accept);
	INIT_FUNC(read);
	INIT_FUNC(write);
	INIT_FUNC(connect);
	INIT_FUNC(close);

	// INIT_FUNC(close);
	// INIT_FUNC(setsockopt);
	// INIT_FUNC(shutdown);
	// INIT_FUNC(writev);
}

void tle_engine(void)
{
	net_lcore_tcp_req();
	net_lcore_tcp_rst();
	// netfe_lcore_tcp();
	net_lcore_tcp();
}
void tle_input(struct rte_mbuf *pkt[], int num)
{
	int32_t rc = 0, n = 0;
	struct tle_dev *dev = RTE_PER_LCORE(tldk_ctx)->dev;
	struct rte_mbuf *rp[num];

	n = tle_tcp_rx_bulk(dev, pkt, rp, &rc, num);
	if (num - n > 0)
	{
		// free rp[num - n]
	}
}

int socket(int domain, int type, int protocol)
{
	int32_t lcore, fd;
	struct netfe_stream *fes;
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);

	if (!inited)
	{
		RTE_LOG(NOTICE, USER1, "socket: not inited\n");
		return real_socket(domain, type, protocol);
	}

	lcore = rte_lcore_id();

	if (domain != AF_INET && domain != AF_INET6 && type != SOCK_STREAM && type != SOCK_DGRAM)
	{
		return -1;
	}

	fes = netfe_get_stream(&tldk_ctx->free);

	if (fes == NULL)
	{
		rte_errno = ENOBUFS;
		return -1;
	}

	RTE_LOG(NOTICE, USER1,
			"%s(%u)={s=%p, p=%d, rxev=%p, txev=%p}\n",
			__func__, lcore, fes->s, protocol,
			fes->rxev, fes->txev);

	// fes->proto = becfg.proto;
	// fes->family = sprm->local_addr.ss_family;
	// fes->laddr = sprm->local_addr;
	netfe_put_stream(&tldk_ctx->use, fes);

	fd = STREAM_TO_FD(fes, lcore);
	RTE_LOG(NOTICE, USER1, "socket(%d): fes %p, fd %d\n", lcore, fes, fd);

	return fd;
}
int bind(int sd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct netfe_stream *fes = NULL;
	struct sockaddr daddr;
	const struct sockaddr_in *lin4;
	const struct sockaddr_in6 *lin6;
	uint16_t port;
	int rc;
	struct tldk_ctx *tldk_ctx;
	struct tle_ctx *ctx;
	struct tle_tcp_stream_param tprm;

	(void)addrlen;

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		RTE_LOG(NOTICE, USER1, "bind: not inited\n");
		return real_bind(sd, addr, addrlen);
	}

	fes = FD_TO_STREAM(sd);
	tldk_ctx = RTE_PER_LCORE(tldk_ctx);
	ctx = tldk_ctx->ctx;
	fes->rxev = tle_event_alloc(tldk_ctx->syneq, fes);
	if (fes->rxev == NULL)
	{
		netfe_stream_close_tcp(fes);
		rte_errno = ENOMEM;
		return -1;
	}

	/* activate rx, tx and err events for the stream */
	tle_event_active(fes->txev, TLE_SEV_DOWN);
	fes->stat.txev[TLE_SEV_DOWN]++;

	tle_event_active(fes->rxev, TLE_SEV_DOWN);
	fes->stat.rxev[TLE_SEV_DOWN]++;

	tle_event_active(fes->erev, TLE_SEV_DOWN);
	fes->stat.erev[TLE_SEV_DOWN]++;

	memset(&tprm, 0, sizeof(tprm));

	memset(&daddr, 0, sizeof(daddr));
	daddr.sa_family = addr->sa_family;

	tprm.addr.local = *(const struct sockaddr_storage *)addr;
	tprm.addr.remote = *(const struct sockaddr_storage *)&daddr;
	// tprm.addr.remote = addr->remote_addr;
	tprm.cfg.err_ev = fes->erev;
	tprm.cfg.recv_ev = fes->rxev;
	tprm.cfg.send_ev = fes->txev;

	fes->s = tle_tcp_stream_open(ctx, &tprm);

	if (fes->s == NULL)
	{
		rc = rte_errno;
		netfe_stream_close_tcp(fes);
		rte_errno = rc;

		if (addr->sa_family == AF_INET)
		{
			lin4 = (const struct sockaddr_in *)addr;

			port = lin4->sin_port;
		}
		else if (addr->sa_family == AF_INET6)
		{
			lin6 = (const struct sockaddr_in6 *)addr;
			port = lin6->sin6_port;
		}

		RTE_LOG(ERR, USER1, "stream open failed for port %u with error code=%u\n",
				port, rc);
		return -1;
	}
	return 0;
}
int listen(int sd, int backlog)
{
	struct netfe_stream *fes = NULL;
	int rc, lcore;

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		return real_listen(sd, backlog);
	}

	if (backlog > TLE_MAX_BACKLOG)
	{
		return -1;
	}

	lcore = rte_lcore_id();
	fes = FD_TO_STREAM(sd);
	if (!fes->s)
	{
		// this socket is closed
		return -1;
	}
	rc = tle_tcp_stream_listen(fes->s);
	RTE_LOG(INFO, USER1,
			"%s(%u) tle_tcp_stream_listen(stream=%p) "
			"returns %d\n",
			__func__, lcore, fes->s, rc);
	return rc;
}
int accept(int sd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct netfe_stream *fes = NULL;
	struct netfe_stream *ts;
	struct tle_stream *rs[TLE_MAX_BACKLOG];
	struct netfe_stream *fs[TLE_MAX_BACKLOG];
	struct tle_tcp_stream_cfg prm[TLE_MAX_BACKLOG];
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);
	int i, n, k, lcore;

	// RTE_LOG(NOTICE, USER1, "accept: fes %p, fd %d\n", fes, sockfd);

	(void)addr;
	(void)addrlen;

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		return real_accept(sd, addr, addrlen);
	}

	lcore = rte_lcore_id();
	fes = FD_TO_STREAM(sd);

	if (!fes->s)
	{
		// this socket is closed
		return -1;
	}
	/* check if any syn requests are waiting */
	n = tle_tcp_stream_accept(fes->s, rs, RTE_DIM(rs));
	if (n == 0)
	{
		return -1;
	}

	NETFE_TRACE("%s(%u): tle_tcp_stream_accept(%p, %u) returns %u\n",
				__func__, lcore, fes->s, TLE_MAX_BACKLOG, n);

	n = 1;
	/* get n free streams */
	k = netfe_get_streams(&tldk_ctx->free, fs, n);
	if (n != k)
	{
		RTE_LOG(ERR, USER1,
				"%s(lc=%u): not enough FE resources to handle %u new "
				"TCP streams;\n",
				__func__, lcore, n - k);
	}

	/* fill accept params to accept k connection requests*/
	for (i = 0; i != k; i++)
	{

		ts = fs[i];
		ts->s = rs[i];
		ts->op = fes->op;
		ts->proto = fes->proto;
		ts->family = fes->family;
		ts->txlen = fes->txlen;
		ts->rxlen = fes->rxlen;

		tle_event_active(ts->erev, TLE_SEV_DOWN);
		tle_event_active(ts->txev, TLE_SEV_DOWN);
		tle_event_active(ts->rxev, TLE_SEV_DOWN);

		netfe_put_stream(&tldk_ctx->use, ts);

		memset(&prm[i], 0, sizeof(prm[i]));
		prm[i].recv_ev = ts->rxev;
		prm[i].send_ev = ts->txev;
		prm[i].err_ev = ts->erev;

		prm[i].recv_ev = ts->rxev;
		prm[i].send_ev = ts->txev;
		prm[i].err_ev = ts->erev;
	}

	tle_tcp_stream_update_cfg(rs, prm, k);

	tle_tcp_stream_close_bulk(rs + k, n - k);

	return STREAM_TO_FD(fs[0], lcore);
}

ssize_t
read(int sd, void *buf, size_t len)
{
	ssize_t sz;
	struct netfe_stream *fes = NULL;
	const struct iovec iv = {
		.iov_base = buf,
		.iov_len = len,
	};

	// NETFE_TRACE("lcore(%d): %s(%d, %p, %zu);\n",
	// 			rte_lcore_id(), __func__, sd, buf, len);

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		return real_read(sd, buf, len);
	}

	fes = FD_TO_STREAM(sd);

	if (!fes->s)
	{
		// this socket is closed
		return 0;
	}
	// sock_stat.nb_recv++;

	sz = tle_tcp_stream_readv(fes->s, &iv, 1);
	if (sz < 0)
	{
		errno = rte_errno;
	}
	else if (sz == 0 && fes->posterr == 0)
	{
		errno = EAGAIN;
		sz = -1;
	}

	// NETFE_TRACE("lcore(%d): %s(%d, %p, %zu) returns %zd;\n",
	// 			rte_lcore_id(), __func__, sd, buf, len, sz);
	return sz;
}

ssize_t
write(int sd, const void *buf, size_t len)
{
	ssize_t sz;
	uint32_t sid, lcore = rte_lcore_id();
	struct netfe_stream *fes = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	const struct iovec iv = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
#pragma GCC diagnostic push

	NETFE_TRACE("lore(%d): %s(%d, %p, %zu);\n",
				lcore, __func__, sd, buf, len);

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		return real_write(sd, buf, len);
	}

	fes = FD_TO_STREAM(sd);
	if (!fes->s)
	{
		// this socket is closed
		return 0;
	}

	sid = rte_lcore_to_socket_id(lcore) + 1;
	assert(sid < RTE_DIM(mpool) && mpool[sid]);

	// sock_stat.nb_writev++;

	sz = tle_tcp_stream_writev(fes->s, mpool[sid], &iv, 1);
	if (sz < 0)
		errno = rte_errno;

	NETFE_TRACE("lore(%d): %s(%d, %p, %zu) returns %zd;\n",
				lcore, __func__, sd, buf, len, sz);
	return sz;
}
int connect(int sd, const struct sockaddr *raddr, socklen_t addrlen)
{
	int rc;
	struct netfe_stream *fes = NULL;
	struct sockaddr_in laddr;
	struct tle_tcp_stream_param tprm;
	struct tle_ctx *ctx;

	// NETFE_TRACE("lcore(%d): %s(%d, %p, %zu);\n",
	// 			rte_lcore_id(), __func__, sd, buf, len);

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		return real_connect(sd, raddr, addrlen);
	}

	fes = FD_TO_STREAM(sd);
	ctx = RTE_PER_LCORE(tldk_ctx)->ctx;

	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_ANY);

	fes->stat.erev[TLE_SEV_DOWN]++;

	memset(&tprm, 0, sizeof(tprm));
	// laddr.sin_port = htons(12345;)
	tprm.addr.local = *(const struct sockaddr_storage *)&laddr;
	tprm.addr.remote = *(const struct sockaddr_storage *)raddr;
	tprm.cfg.err_ev = fes->erev;
	tprm.cfg.recv_ev = fes->rxev;

	fes->s = tle_tcp_stream_open(ctx, &tprm);
	if (fes->s == NULL)
	{
		rc = rte_errno;
		netfe_stream_close_tcp(fes);
		rte_errno = rc;
		return -1;
	}

	rc = tle_tcp_stream_connect(fes->s, raddr);

	return rc;
}

int close(int sd)
{
	// int rc;
	// struct tle_stream *s;
	struct netfe_stream *fes = NULL;
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);

	if (!inited || !IS_VALID_TLE_FD(sd))
	{
		return real_close(sd);
	}

	fes = FD_TO_STREAM(sd);

	if (!fes->s)
	{
		// this socket is closed
		return 0;
	}

	// shall we free fes->s?
	tle_event_idle(fes->erev);
	tle_event_idle(fes->rxev);
	tle_event_idle(fes->txev);
	tle_tcp_stream_close(fes->s);
	fes->s = NULL;
	fes->posterr = 0;

	netfe_rem_stream(&tldk_ctx->use, fes);
	netfe_put_stream(&tldk_ctx->free, fes);

	return 0;
}

/***************** some helper function for example *****************/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

static int
netbe_dest_init(const char *fname, struct netbe_cfg *cfg)
{
	int32_t rc;
	uint32_t f, i, p;
	uint32_t k, l, cnt;
	struct netbe_lcore *lc;
	struct netbe_dest_prm prm;

	rc = netbe_parse_dest(fname, &prm);
	if (rc != 0)
		return rc;

	rc = 0;
	for (i = 0; i != prm.nb_dest; i++)
	{

		p = prm.dest[i].port;
		f = prm.dest[i].family;

		cnt = 0;
		for (k = 0; k != cfg->cpu_num; k++)
		{
			lc = cfg->cpu + k;
			for (l = 0; l != lc->prtq_num; l++)
				if (lc->prtq[l].port.id == p)
				{
					rc = netbe_add_dest(lc, l, f,
										prm.dest + i, 1);
					if (rc != 0)
					{
						RTE_LOG(ERR, USER1,
								"%s(lc=%u, family=%u) "
								"could not add "
								"destinations(%u)\n",
								__func__, lc->id, f, i);
						return -ENOSPC;
					}
					cnt++;
				}
		}

		if (cnt == 0)
		{
			RTE_LOG(ERR, USER1, "%s(%s) error at line %u: "
								"port %u not managed by any lcore;\n",
					__func__, fname, prm.dest[i].line, p);
			break;
		}
	}

	free(prm.dest);
	return rc;
}

int sock_global_init(int argc, char *argv[])
{
	int32_t rc;
	uint32_t i;
	struct tle_ctx_param ctx_prm;
	struct netfe_lcore_prm feprm;
	// struct rte_eth_stats stats;
	char fecfg_fname[PATH_MAX + 1];
	char becfg_fname[PATH_MAX + 1];
	struct rte_eth_dev_info dev_info;

	fecfg_fname[0] = 0;
	becfg_fname[0] = 0;
	memset(g_prm, 0, sizeof(g_prm));

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
				 "%s: rte_eal_init failed with error code: %d\n",
				 __func__, rc);

	memset(&ctx_prm, 0, sizeof(ctx_prm));
	ctx_prm.timewait = TLE_TCP_TIMEWAIT_DEFAULT;

	signal(SIGINT, sig_handle);

	argc -= rc;
	argv += rc;

	// argv = "--lcores=2,3 ..."
	rc = parse_app_options(argc, argv, &becfg, &ctx_prm,
						   fecfg_fname, becfg_fname);
	if (rc != 0)
		rte_exit(EXIT_FAILURE,
				 "%s: parse_app_options failed with error code: %d\n",
				 __func__, rc);

	/* init all the function pointer */
	// func_ptrs_init(becfg.proto);

	rc = netbe_port_init(&becfg);
	if (rc != 0)
		rte_exit(EXIT_FAILURE,
				 "%s: netbe_port_init failed with error code: %d\n",
				 __func__, rc);

	rc = netbe_lcore_init(&becfg, &ctx_prm);
	if (rc != 0)
		sig_handle(SIGQUIT);

	rc = netbe_dest_init(becfg_fname, &becfg);
	if (rc != 0)
		sig_handle(SIGQUIT);

	for (i = 0; i != becfg.prt_num && rc == 0; i++)
	{
		RTE_LOG(NOTICE, USER1, "%s: starting port %u\n",
				__func__, becfg.prt[i].id);
		rc = rte_eth_dev_start(becfg.prt[i].id);
		if (rc != 0)
		{
			RTE_LOG(ERR, USER1,
					"%s: rte_eth_dev_start(%u) returned "
					"error code: %d\n",
					__func__, becfg.prt[i].id, rc);
			sig_handle(SIGQUIT);
		}
		rte_eth_dev_info_get(becfg.prt[i].id, &dev_info);
		rc = update_rss_reta(&becfg.prt[i], &dev_info);
		if (rc != 0)
			sig_handle(SIGQUIT);
	}

	feprm.max_streams = ctx_prm.max_streams * becfg.cpu_num;

	rc = (rc != 0) ? rc : netfe_parse_cfg(fecfg_fname, &feprm);
	if (rc != 0)
		sig_handle(SIGQUIT);

	for (i = 0; rc == 0 && i != becfg.cpu_num; i++)
		g_prm[becfg.cpu[i].id].be.lc = becfg.cpu + i;

	rc = (rc != 0) ? rc : netfe_lcore_fill(g_prm, &feprm);
	if (rc != 0)
		sig_handle(SIGQUIT);

	return 0;
}

int sock_local_init(void)
{
	int32_t rc;
	uint32_t lcore;
	struct lcore_prm *prm;

	lcore = rte_lcore_id();
	prm = &g_prm[lcore];

	RTE_LOG(NOTICE, USER1, "%s(lcore=%u) start\n",
			__func__, lcore);

	rc = 0;

	/* lcore FE init. */
	// if (prm->fe.max_streams != 0)
	// 	rc = netfe_lcore_init_tcp(&prm->fe);

	/* lcore FE init. */
	if (rc == 0 && prm->be.lc != NULL)
		rc = netbe_lcore_setup(prm->be.lc);

	if (rc != 0)
	{
		sig_handle(SIGQUIT);
	}
	// inited = 1;

	return 0;
}
#pragma GCC diagnostic pop
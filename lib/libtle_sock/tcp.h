/*
 * Copyright (c) 2016  Intel Corporation.
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

#ifndef TCP_H_
#define TCP_H_

#define	TCP_MAX_PROCESS	0x20
RTE_DECLARE_PER_LCORE(struct tldk_ctx *, tldk_ctx);

static inline void
netfe_stream_term_tcp(struct netfe_stream *fes)
{
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);
	struct netfe_stream_list *free = &tldk_ctx->free;
	// struct netfe_stream_list *free = RTE_PER_LCORE(free);

	fes->s = NULL;
	fes->fwds = NULL;
	fes->posterr = 0;
	memset(&fes->stat, 0, sizeof(fes->stat));
	pkt_buf_empty(&fes->pbuf);
	netfe_put_stream(free, fes);
}

static inline void
netfe_stream_close_tcp(struct netfe_stream *fes)
{
	tle_tcp_stream_close(fes->s);
	netfe_stream_term_tcp(fes);
}

static inline void
netfe_new_conn_tcp(struct tldk_ctx *tldk_ctx, uint32_t lcore,
				   struct netfe_stream *fes)
{
	uint32_t i, k, n;
	struct netfe_stream *ts;
	struct tle_stream *rs[MAX_PKT_BURST];
	struct netfe_stream *fs[MAX_PKT_BURST];
	struct tle_tcp_stream_cfg prm[MAX_PKT_BURST];

	/* check if any syn requests are waiting */
	n = tle_tcp_stream_accept(fes->s, rs, RTE_DIM(rs));
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_tcp_stream_accept(%p, %u) returns %u\n",
		__func__, lcore, fes->s, MAX_PKT_BURST, n);

	/* get n free streams */
	k = netfe_get_streams(&tldk_ctx->free, fs, n);
	if (n != k)
		RTE_LOG(ERR, USER1,
			"%s(lc=%u): not enough FE resources to handle %u new "
			"TCP streams;\n",
			__func__, lcore, n - k);

	/* fill accept params to accept k connection requests*/
	for (i = 0; i != k; i++) {

		ts = fs[i];
		ts->s = rs[i];
		ts->op = fes->op;
		ts->proto = fes->proto;
		ts->family = fes->family;
		ts->txlen = fes->txlen;
		ts->rxlen = fes->rxlen;

		tle_event_active(ts->erev, TLE_SEV_DOWN);
		if (fes->op == TXONLY || fes->op == FWD) {
			tle_event_active(ts->txev, TLE_SEV_UP);
			ts->stat.txev[TLE_SEV_UP]++;
		}
		if (fes->op != TXONLY) {
			tle_event_active(ts->rxev, TLE_SEV_DOWN);
			ts->stat.rxev[TLE_SEV_DOWN]++;
		}

		netfe_put_stream(&tldk_ctx->use, ts);

		memset(&prm[i], 0, sizeof(prm[i]));
		prm[i].recv_ev = ts->rxev;
		prm[i].send_ev = ts->txev;
		prm[i].err_ev = ts->erev;
	}

	tle_tcp_stream_update_cfg(rs, prm, k);

	tle_tcp_stream_close_bulk(rs + k, n - k);

	// /* for the forwarding mode, open the second one */
	// if (fes->op == FWD) {
	// 	for (i = 0; i != k; i++) {

	// 		ts = fs[i];

	// 		ts->fwds = netfe_create_fwd_stream(tldk_ctx, fes, lcore,
	// 										   fes->fwdprm.bidx);
	// 		if (ts->fwds != NULL)
	// 			ts->fwds->fwds = ts;
	// 	}
	// }

	tldk_ctx->tcp_stat.acc += k;
	tldk_ctx->tcp_stat.rej += n - k;
}

static inline void
net_lcore_tcp_req(void)
{
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);
	uint32_t j, n, lcore;
	struct netfe_stream *fs[MAX_PKT_BURST];

	if (tldk_ctx == NULL)
		return;

	/* look for syn events */
	n = tle_evq_get(tldk_ctx->syneq, (const void **)(uintptr_t)fs, RTE_DIM(fs));
	if (n == 0)
		return;

	lcore = rte_lcore_id();

	NETFE_TRACE("%s(%u): tle_evq_get(synevq=%p) returns %u\n",
				__func__, lcore, tldk_ctx->syneq, n);

	for (j = 0; j != n; j++)
		netfe_new_conn_tcp(tldk_ctx, lcore, fs[j]);
}

static inline void
net_lcore_tcp_rst(void)
{
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);
	struct netfe_stream *fwds;
	uint32_t j, k, n;
	struct tle_stream *s[MAX_PKT_BURST];
	struct netfe_stream *fs[MAX_PKT_BURST];
	struct tle_event *rv[MAX_PKT_BURST];
	struct tle_event *tv[MAX_PKT_BURST];
	struct tle_event *ev[MAX_PKT_BURST];

	if (tldk_ctx == NULL)
		return;

	/* look for err events */
	n = tle_evq_get(tldk_ctx->ereq, (const void **)(uintptr_t)fs, RTE_DIM(fs));
	if (n == 0)
		return;

	NETFE_TRACE("%s(%u): tle_evq_get(errevq=%p) returns %u\n",
				__func__, rte_lcore_id(), tldk_ctx->ereq, n);

	k = 0;
	for (j = 0; j != n; j++) {
		if (verbose > VERBOSE_NONE) {
			struct tle_tcp_stream_addr addr;
			tle_tcp_stream_get_addr(fs[j]->s, &addr);
			netfe_stream_dump(fs[j], &addr.local, &addr.remote);
		}

		/* check do we still have something to send/recv */
		if (fs[j]->posterr == 0 &&
				(tle_event_state(fs[j]->rxev) == TLE_SEV_UP ||
				tle_event_state(fs[j]->txev) == TLE_SEV_UP)) {
			fs[j]->posterr++;
		} else {
			s[k] = fs[j]->s;
			rv[k] = fs[j]->rxev;
			tv[k] = fs[j]->txev;
			ev[k] = fs[j]->erev;
			fs[k] = fs[j];
			k++;
		}
	}

	if (k == 0)
		return;

	tle_evq_idle(tldk_ctx->rxeq, rv, k);
	tle_evq_idle(tldk_ctx->txeq, tv, k);
	tle_evq_idle(tldk_ctx->ereq, ev, k);

	tle_tcp_stream_close_bulk(s, k);

	for (j = 0; j != k; j++) {

		/* if forwarding mode, signal peer stream to terminate too. */
		fwds = fs[j]->fwds;
		if (fwds != NULL && fwds->s != NULL) {

			fwds->fwds = NULL;
			tle_event_raise(fwds->erev);
			fs[j]->fwds = NULL;
		}

		/* now terminate the stream receiving rst event*/
		netfe_rem_stream(&tldk_ctx->use, fs[j]);
		netfe_stream_term_tcp(fs[j]);
		tldk_ctx->tcp_stat.ter++;
	}
}

static inline int
net_rxtx_process_tcp(__rte_unused uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;
	struct rte_mbuf **pkt;

	n = fes->pbuf.num;
	pkt = fes->pbuf.pkt;

	/* there is nothing to send. */
	if (n == 0) {
		tle_event_idle(fes->txev);
		fes->stat.txev[TLE_SEV_IDLE]++;
		return 0;
	}


	k = tle_tcp_stream_send(fes->s, pkt, n);

	NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto],
		fes->s, n, k);
	fes->stat.txp += k;
	fes->stat.drops += n - k;

	/* not able to send anything. */
	if (k == 0)
		return 0;

	/* Mark stream for reading if:
	 * ECHO: Buffer full
	 * RXTX: All outbound packets successfully dispatched
	 */
	if ((fes->op == ECHO && n == RTE_DIM(fes->pbuf.pkt)) ||
			(fes->op == RXTX && n - k == 0)) {
		/* mark stream as readable */
		tle_event_active(fes->rxev, TLE_SEV_UP);
		fes->stat.rxev[TLE_SEV_UP]++;
	}

	/* adjust pbuf array. */
	fes->pbuf.num = n - k;
	for (i = 0; i != n - k; i++)
		pkt[i] = pkt[i + k];

	return k;
}

static inline int
netfe_tx_process_tcp(uint32_t lcore, struct netfe_stream *fes)
{
	uint32_t i, k, n;

	/* refill with new mbufs. */
	if (fes->posterr == 0)
		pkt_buf_fill(lcore, &fes->pbuf, fes->txlen);

	n = fes->pbuf.num;
	if (n == 0)
		return 0;

	/**
	 * TODO: cannot use function pointers for unequal param num.
	 */
	k = tle_tcp_stream_send(fes->s, fes->pbuf.pkt, n);

	NETFE_TRACE("%s(%u): tle_%s_stream_send(%p, %u) returns %u\n",
		__func__, lcore, proto_name[fes->proto], fes->s, n, k);
	fes->stat.txp += k;
	fes->stat.drops += n - k;

	if (k == 0)
		return 0;

	/* adjust pbuf array. */
	fes->pbuf.num = n - k;
	for (i = k; i != n; i++)
		fes->pbuf.pkt[i - k] = fes->pbuf.pkt[i];

	return k;
}

static inline void
net_lcore_tcp(void)
{
	struct tldk_ctx *tldk_ctx = RTE_PER_LCORE(tldk_ctx);
	struct tle_dev *dev;
	if (tldk_ctx == NULL)
		return;

	// for (i = 0; i != max_port; i++)
	{
		dev = tldk_ctx->dev;
		tle_dev_rx(dev);
		tle_tcp_process(tldk_ctx->ctx, TCP_MAX_PROCESS);
		tle_dev_tx(dev);
	}
}

#endif /* TCP_H_ */

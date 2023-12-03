#ifndef __TLE_IP_H__
#define __TLE_IP_H__

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include "tle_ctx.h"

void add_route(uint32_t dest, uint32_t mask, uint32_t next_hop,
               const char *next_hop_mac, struct tle_dev *dev, int metric);
void delete_route(uint32_t dest, uint32_t mask);
int search_best_match_route(struct rte_mempool *mp, unsigned int dip, struct tle_dest *dest);

#endif

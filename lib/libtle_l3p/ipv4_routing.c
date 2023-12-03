#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_ip.h>

#include "tle_ip.h"

int test_route(void);
void print_route_table(void);

// Define a structure for a routing table entry

struct route_entry
{
    uint32_t dest;            // Destination network address in network byte order
    uint32_t mask;            // Subnet mask in network byte order
    uint32_t next_hop;        // Next hop address in network byte order
    uint32_t mtu;
    char next_hop_mac[RTE_ETHER_ADDR_LEN]; // Next hop mac address
    struct tle_dev *dev;
    int metric;               // Metric value
    struct route_entry *next; // Pointer to the next entry in the list
};

// Create a linked list of routing table entries, TODO: use radix tree
struct route_entry *routing_table = NULL;

// Add a new entry to the routing table
void add_route(uint32_t dest, uint32_t mask, uint32_t next_hop,
               const char *next_hop_mac, struct tle_dev *dev, int metric)
{
    // Allocate memory for a new entry
    int socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    struct route_entry *new_entry = rte_zmalloc_socket(NULL, sizeof(struct route_entry), RTE_CACHE_LINE_SIZE, socket_id);
    if (new_entry == NULL)
    {
        printf("malloc failed for route entry\n");
        return;
    }

    // Initialize the fields of the new entry
    new_entry->dev = dev;
    new_entry->dest = dest;
    new_entry->mask = mask;
    new_entry->next_hop = next_hop;
    new_entry->metric = metric;
    new_entry->next = NULL;
    new_entry->mtu = 1500;
    rte_ether_addr_copy((const struct rte_ether_addr *)next_hop_mac, (struct rte_ether_addr *)new_entry->next_hop_mac);
    // Insert the new entry at the head of the list
    new_entry->next = routing_table;

    routing_table = new_entry;
}

// Delete an entry from the routing table
void delete_route(uint32_t dest, uint32_t mask)
{
    // Find the entry to delete
    struct route_entry *prev = NULL;
    struct route_entry *curr = routing_table;
    while (curr != NULL)
    {
        if (curr->dest == dest && curr->mask == mask)
        {
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    // If the entry is not found, do nothing
    if (curr == NULL)
    {
        return;
    }
    // If the entry is the head of the list, update the routing table pointer
    if (prev == NULL)
    {
        routing_table = curr->next;
    }
    // Otherwise, update the previous entry's next pointer
    else
    {
        prev->next = curr->next;
    }
    // Free the memory of the deleted entry
    free(curr);
}

static void
route_fill_dst(struct rte_mempool *mp, struct tle_dest *dst, uint16_t l3_type, uint8_t proto_id, struct route_entry *re)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip4h;
    struct rte_ipv6_hdr *ip6h;

    dst->head_mp = mp;
    dst->mtu = re->mtu;
    dst->l2_len = sizeof(*eth);
    dst->dev = re->dev;
    // dst->ol_flags = re->dev

    eth = (struct rte_ether_hdr *)dst->hdr;

    // rte_ether_addr_copy((struct rte_ether_addr *)tle_get_dev_mac(re->dev), &eth->src_addr);
    rte_ether_addr_copy((struct rte_ether_addr *)re->next_hop_mac, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(l3_type);

    if (l3_type == RTE_ETHER_TYPE_IPV4)
    {
        dst->l3_len = sizeof(*ip4h);
        ip4h = (struct rte_ipv4_hdr *)(eth + 1);
        ip4h->version_ihl = 4 << 4 |
                            sizeof(*ip4h) / RTE_IPV4_IHL_MULTIPLIER;
        ip4h->time_to_live = 64;
        ip4h->next_proto_id = proto_id;
    }
    else if (l3_type == RTE_ETHER_TYPE_IPV6)
    {
        dst->l3_len = sizeof(*ip6h);
        ip6h = (struct rte_ipv6_hdr *)(eth + 1);
        ip6h->vtc_flow = 6 << 4;
        ip6h->proto = proto_id;
        ip6h->hop_limits = 64;
    }
}

// A function to search the best match routing entry for a given destination IP address
int search_best_match_route(struct rte_mempool *mp, unsigned int dip, struct tle_dest *dest)
{
    struct route_entry *best_match = NULL; // The best match entry
    int longest_match = -1;                // The longest prefix match length
    struct route_entry *entry = routing_table;
    while (entry)
    { // Iterate over the routing table
        // Perform bitwise AND operation between the destination and the mask
        unsigned int masked_dest = dip & entry->mask;
        // Compare the masked destination with the network address
        if (masked_dest == entry->dest)
        {
            // Count the number of bits in the mask
            int bit_count = __builtin_popcount(entry->mask); // GCC built-in function
            // Update the best match and the longest match if the current entry has a longer prefix match
            if (bit_count > longest_match)
            {
                best_match = entry;
                longest_match = bit_count;
            }
        }
        entry = entry->next;
    }
    if (!best_match)
    {
        return -1;
    }
    route_fill_dst(mp, dest, RTE_ETHER_TYPE_IPV4, IPPROTO_TCP, best_match);
    return 0;
}

// Print the routing table
void print_route_table(void)
{
    // Iterate over the list of entries
    struct route_entry *curr = routing_table;
    while (curr != NULL)
    {
        // Convert the network addresses to dotted-decimal notation
        char dest_str[16];
        char mask_str[16];
        char next_str[16];
        inet_ntop(AF_INET, &curr->dest, dest_str, 16);
        inet_ntop(AF_INET, &curr->mask, mask_str, 16);
        inet_ntop(AF_INET, &curr->next, next_str, 16);
        // Print the entry fields
        printf("%s/%s via %s dev %p metric %d\n", dest_str, mask_str, next_str, curr->dev, curr->metric);
        // Move to the next entry
        curr = curr->next;
    }
}

// Test the routing table functions
// int test_route(void)
// {
//     // Add some entries to the routing table
//     add_route(inet_addr("192.168.1.0"), inet_addr("255.255.255.0"), inet_addr("192.168.1.1"), "", "eth0", 1);
//     add_route(inet_addr("10.0.0.0"), inet_addr("255.0.0.0"), inet_addr("10.0.0.1"), "", "eth1", 2);
//     add_route(inet_addr("0.0.0.0"), inet_addr("0.0.0.0"), inet_addr("192.168.1.1"), "", "eth0", 0);
//     // Print the routing table
//     print_route_table();
//     // Delete an entry from the routing table
//     delete_route(inet_addr("10.0.0.0"), inet_addr("255.0.0.0"));
//     // Print the routing table again
//     print_route_table();
//     // Free the memory of the routing table
//     struct route_entry *curr = routing_table;
//     while (curr != NULL)
//     {
//         struct route_entry *next = curr->next;
//         free(curr);
//         curr = next;
//     }
//     return 0;
// }
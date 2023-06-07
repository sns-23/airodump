#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>

#include <pcap.h>
#include <pthread.h>

#include "ieee80211_radiotap.h"
#include "list.h"
#include "util.h"

#define __packed __attribute__((packed))

#define BEACON_FRM 0x0080
#define MAX_SSID_LEN 32
#define RELOAD_SEC 1

struct beacon_frm_opt {
    uint8_t id;
    uint8_t len;
    char data[0];
} __packed;

struct beacon_frm_body {
    uint64_t timestamp;
    uint16_t interval;
    uint16_t cap_info;
    struct beacon_frm_opt opts[0];
} __packed;

struct beacon_frm {
    uint16_t frm_ctrl;
    uint16_t duration_id;
    uint8_t dmac[ETH_ALEN];
    uint8_t smac[ETH_ALEN];
    uint8_t bssid[ETH_ALEN];
    uint16_t seq_ctl;
    struct beacon_frm_body body;
    // u32 fcs;
} __packed;

struct info {
    uint8_t bssid[ETH_ALEN];
    int beacons;
    char essid[MAX_SSID_LEN];
};

struct info_node {
    struct list_head list;
    struct info info;
};

LIST_HEAD(info_list);
pthread_mutex_t info_list_lock;

void usage(void) 
{
    puts("syntax : airodump <interface>");
    puts("sample : airodump mon0");
}

char *eth_ntoa(uint8_t eth_addr[ETH_ALEN])
{
    static char buf[ETH_ALEN * 3];

    sprintf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
            eth_addr[0], eth_addr[1], eth_addr[2], eth_addr[3], eth_addr[4], eth_addr[5]);

    return buf;
}

pcap_t *init_pcap(char *interface)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        pr_err("pcap_open_live(%s)\n", interface);
        return NULL;
    }

    return handle;
}

int recv_pkt(pcap_t *handle, void *buf, size_t n)
{
    struct pcap_pkthdr* header;
    const u_char* packet;
    int ret;

    while (true) {
		ret = pcap_next_ex(handle, &header, &packet);
		if (ret == 0) 
            continue;
		if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", ret, pcap_geterr(handle));
			return -1;
        }
		if (ret > 0)
            break;
    }

    memcpy(buf, packet, header->len);
    return header->len;
}

int add_new_frm(struct info *info)
{
    struct info_node *new_node;
    new_node = malloc(sizeof(*new_node));
    if (new_node == NULL)
        return -1;
    
    memcpy(&new_node->info, info, sizeof(*info));

    pthread_mutex_lock(&info_list_lock);
    list_add_tail(&new_node->list, &info_list);
    pthread_mutex_unlock(&info_list_lock);

    return 0;
}

void delete_all_frm()
{
    struct info_node *cur;

    pthread_mutex_lock(&info_list_lock);
    list_for_each_entry(cur, &info_list, list) {
        list_del(&cur->list);
        free(cur);
    }
    pthread_mutex_unlock(&info_list_lock);
}

bool find_bssid(uint8_t bssid[ETH_ALEN]) 
{
    struct info_node *cur;

    pthread_mutex_lock(&info_list_lock);
    list_for_each_entry(cur, &info_list, list) {
        if (memcmp(cur->info.bssid, bssid, ETH_ALEN) == 0) {
            cur->info.beacons++;
            pthread_mutex_unlock(&info_list_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&info_list_lock);

    return false;
}

void print_all_frm(void)
{
    struct info_node *cur;

    while (true) {
        system("clear");
        pr_info("BSSID\t\t\tBeacons\t\tESSID\n");

        pthread_mutex_lock(&info_list_lock);
        list_for_each_entry(cur, &info_list, list) {
            pr_info("%s\t\t%d\t\t%s\n", eth_ntoa(cur->info.bssid), cur->info.beacons, cur->info.essid);
        }
        pthread_mutex_unlock(&info_list_lock);

        sleep(RELOAD_SEC);
    }
}

int airodump_loop(pcap_t *handle)
{
    struct ieee80211_radiotap_header *radiotap_hdr;
    struct beacon_frm *beacon_frm;
    struct info info;
    pthread_t prn_th;
    char pkt[BUFSIZ];
    int pkt_len;

    pthread_mutex_init(&info_list_lock, NULL);
    pthread_create(&prn_th, NULL, print_all_frm, NULL);
    
    while (true) {
        pkt_len = recv_pkt(handle, pkt, BUFSIZ);
        if (pkt_len < 0) {
            pr_err("recv_pkt()\n");
            goto out_error;      
        }

        if (pkt_len < sizeof(*radiotap_hdr))
            continue;
        
        radiotap_hdr = pkt;
        if (pkt_len < radiotap_hdr->it_len)
            continue;

        beacon_frm = (char *)radiotap_hdr + radiotap_hdr->it_len;
        if (beacon_frm->frm_ctrl != BEACON_FRM)
            continue;

        if (find_bssid(beacon_frm->bssid) == true)
            continue;

        memcpy(&info.bssid, &beacon_frm->bssid, ETH_ALEN);
        info.beacons = 1;
        memcpy(info.essid, beacon_frm->body.opts[0].data, beacon_frm->body.opts[0].len);
        info.essid[beacon_frm->body.opts->len] = '\0';

        if (add_new_frm(&info) < 0) {
            pr_err("There is no memory");
            goto out_error;
        }
    }
    
    delete_all_frm();

    pthread_mutex_destroy(&info_list_lock);
    return 0;

out_error:
    pthread_mutex_destroy(&info_list_lock);
    return -1;
}

int main(int argc, char *argv[])
{
    char *interface;
    pcap_t *handle;
    int ret;
    
    if (argc != 2) {
        usage();
        return 0;
    }

    interface = argv[1];

    handle = init_pcap(interface);
    if (handle == NULL)
        return -1;
    
    ret = airodump_loop(handle);
    pcap_close(handle);

    if (ret < 0) {
        pr_err("airodump_loop() returns %d\n", ret);
        return -1;
    }

    return 0;
}
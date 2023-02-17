#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <fcntl.h>

// ARP封装包
typedef struct
{
    struct ether_header eh;
    struct ether_arp arp;
}ARP_PKG_Typedef;


void print_arp_pkg(ARP_PKG_Typedef *arp_pkg)
{
    // 以太帧
    // struct ether_header
    // {
    // uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
    // uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
    // uint16_t ether_type;		        /* packet type ID field	*/
    // } __attribute__ ((__packed__));
    
    printf("dst eht: %02X:%02X:%02X:%02X:%02X:%02X\n", arp_pkg->eh.ether_dhost[0], arp_pkg->eh.ether_dhost[1], arp_pkg->eh.ether_dhost[2], 
        arp_pkg->eh.ether_dhost[3], arp_pkg->eh.ether_dhost[4], arp_pkg->eh.ether_dhost[5]);
    printf("src eht: %02X:%02X:%02X:%02X:%02X:%02X\n", arp_pkg->eh.ether_shost[0], arp_pkg->eh.ether_shost[1], arp_pkg->eh.ether_shost[2], 
        arp_pkg->eh.ether_shost[3], arp_pkg->eh.ether_shost[4], arp_pkg->eh.ether_shost[5]);
    printf("packet type ID:%d\n", arp_pkg->eh.ether_type);

    // ARP帧
    // struct	ether_arp {
    //     struct	arphdr ea_hdr;		/* fixed-size header */
    //     uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
    //     uint8_t arp_spa[4];		/* sender protocol address */
    //     uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
    //     uint8_t arp_tpa[4];		/* target protocol address */
    // };

    // struct arphdr
    // {
    //     unsigned short int ar_hrd;		/* Format of hardware address.  */
    //     unsigned short int ar_pro;		/* Format of protocol address.  */
    //     unsigned char ar_hln;		/* Length of hardware address.  */
    //     unsigned char ar_pln;		/* Length of protocol address.  */
    //     unsigned short int ar_op;		/* ARP opcode (command).  */
    // }
    printf("ar_hrd:%d\n", arp_pkg->arp.ea_hdr.ar_hrd);
    printf("ar_pro:%d\n", arp_pkg->arp.ea_hdr.ar_pro);
    printf("ar_hln:%d\n", arp_pkg->arp.ea_hdr.ar_hln);
    printf("ar_op:%d\n", arp_pkg->arp.ea_hdr.ar_op);

    printf("sender mac:%02X:%02X:%02X:%02X:%02X:%02X\n", 
    arp_pkg->arp.arp_sha[0], arp_pkg->arp.arp_sha[1], arp_pkg->arp.arp_sha[2], 
    arp_pkg->arp.arp_sha[3], arp_pkg->arp.arp_sha[4], arp_pkg->arp.arp_sha[5]);
    printf("sender ip:%d.%d.%d.%d\n", arp_pkg->arp.arp_spa[0], arp_pkg->arp.arp_spa[1], arp_pkg->arp.arp_spa[2], arp_pkg->arp.arp_spa[3]);
    
    printf( "target mac:%02X:%02X:%02X:%02X:%02X:%02X\n", 
        arp_pkg->arp.arp_tha[0], arp_pkg->arp.arp_tha[1], arp_pkg->arp.arp_tha[2], 
        arp_pkg->arp.arp_tha[3], arp_pkg->arp.arp_tha[4], arp_pkg->arp.arp_tha[5]);
    printf("target ip:%d.%d.%d.%d\n", arp_pkg->arp.arp_tpa[0], arp_pkg->arp.arp_tpa[1], arp_pkg->arp.arp_tpa[2], arp_pkg->arp.arp_tpa[3]);
}

void print_sockaddr_ll(struct sockaddr_ll *ll)
{
    // struct sockaddr_ll
    // {
    // unsigned short int sll_family; /* 一般为AF_PACKET */
    // unsigned short int sll_protocol; /* 上层协议 */
    // int sll_ifindex; /* 接口类型 */
    // unsigned short int sll_hatype; /* 报头类型 */
    // unsigned char sll_pkttype; /* 包类型 */
    // unsigned char sll_halen; /* 地址长度 */
    // unsigned char sll_addr[8]; /* MAC地址 */
    // };

    printf("************* struct sockaddr_ll ****************\n");
    printf("sll_family:%d\n", ll->sll_family);
    printf("sll_protocol:0x%x\n", ll->sll_protocol);
    printf("sll_ifindex:%d\n", ll->sll_ifindex);
    printf("sll_hatype:%d\n", ll->sll_hatype);
    printf("sll_halen:%d\n", ll->sll_halen);
    printf("sll_addr:%02X:%02X:%02X:%02X:%02X:%02X\n\n", 
        ll->sll_addr[0], ll->sll_addr[1], ll->sll_addr[2], 
        ll->sll_addr[3], ll->sll_addr[4], ll->sll_addr[5]);
}

int _send_arp(int sockfd, struct sockaddr_ll *peer_addr, ARP_PKG_Typedef *arg_pkg)
{
    int ret = -1;

    printf("who has %d.%d.%d.%d? Tell %d.%d.%d.%d\n", 
        arg_pkg->arp.arp_tpa[0], arg_pkg->arp.arp_tpa[1], arg_pkg->arp.arp_tpa[2], arg_pkg->arp.arp_tpa[3],
        arg_pkg->arp.arp_spa[0], arg_pkg->arp.arp_spa[1], arg_pkg->arp.arp_spa[2], arg_pkg->arp.arp_spa[3]);
    ret = sendto(sockfd, arg_pkg, sizeof(ARP_PKG_Typedef), 0,
                   (struct sockaddr *)peer_addr, sizeof(struct sockaddr_ll));
    
    if(ret < 0)
    {
        perror("sendto");
        close(sockfd);
        exit(-1);
    }
    
    return ret;
}

int send_arp(int socket_fd, const char *ifname, const char *dst_ip)
{
    ARP_PKG_Typedef arp_pkg;
    struct sockaddr_ll peer;
    int ret = -1;
    unsigned char src_ip[4];  
    unsigned char src_mac[6]; 

    //unsigned char dst_ip[4] = {192, 168, 0, 140};  
    unsigned char dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* 获取本地网卡信息 **/
    struct ifreq req;
    bzero(&req, sizeof(struct ifreq));
    strcpy(req.ifr_name, ifname);

    // MAC地址
    if (ioctl(socket_fd, SIOCGIFHWADDR, &req) != 0)
    {
        perror("ioctl()");
        close(socket_fd);
        return -1;
    }
    memcpy(src_mac, req.ifr_hwaddr.sa_data, 6);
    //printf("MAC:%02X:%02X:%02X:%02X:%02X:%02X\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    // IP地址
    if (ioctl(socket_fd, SIOCGIFADDR, &req) != 0)
    {
        perror("ioctl()");
        close(socket_fd);
        return -1;
    }
    memcpy(src_ip, &((struct sockaddr_in*)(&req.ifr_addr))->sin_addr, 4);
    //printf("IP:%d.%d.%d.%d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    
    // 网口
    if (ioctl(socket_fd, SIOCGIFINDEX, &req) != 0)
    {
        perror("ioctl()");
        close(socket_fd);
        return -1;
    }
    memset(&peer, 0, sizeof(peer));
    peer.sll_family = AF_PACKET;
    peer.sll_ifindex = req.ifr_ifindex;
    peer.sll_protocol = htons(ETH_P_ARP);
    memset(&arp_pkg, 0 ,sizeof(arp_pkg));
    
    // 填充以太网头部
    memcpy(arp_pkg.eh.ether_dhost, dst_mac, 6); // 目的MAC地址
    memcpy(arp_pkg.eh.ether_shost, src_mac, 6); // 源MAC地址
    arp_pkg.eh.ether_type = htons(ETH_P_ARP);   // 协议
	
    // 填充ARP报文头部
    arp_pkg.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER); // 硬件类型
    arp_pkg.arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP); // 协议类型 ETHERTYPE_IP | ETH_P_IP
    arp_pkg.arp.ea_hdr.ar_hln = 6;                   // 硬件地址长度
    arp_pkg.arp.ea_hdr.ar_pln = 4;                   // 协议地址长度
    arp_pkg.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST); // ARP请求操作

    in_addr_t tadd = 0;
    tadd = inet_addr(dst_ip);

    memcpy(arp_pkg.arp.arp_sha, src_mac, 6);         // 源MAC地址
    memcpy(arp_pkg.arp.arp_spa, src_ip, 4);          // 源IP地址
    memcpy(arp_pkg.arp.arp_tha, dst_mac, 6);         // 目的MAC地址
    memcpy(arp_pkg.arp.arp_tpa, (uint8_t*)&tadd, 4);          // 目的IP地址
    _send_arp(socket_fd, &peer, &arp_pkg);
}

int print_all_net_interface_info(void)
{
    int sock = -1;
	char buf[64];
    #define MAXN 10
    struct ifreq interfaces[MAXN];

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sock < 0)
    {
        perror("socket");
        return -1;
    }

    // get if vector
    struct ifconf ifconf = {
		.ifc_len = sizeof(interfaces),
		.ifc_req = interfaces,
    };
    struct ifreq *i = interfaces;

	//获取所有网络接口信息
	ioctl(sock, SIOCGIFCONF, &ifconf);
	int num = ifconf.ifc_len/sizeof(struct ifreq);
	printf("interfaces nums = %d\n",num);
	
	for (int j=0; j<num; ++j,i++) 
    {
		printf("[%d]:%s: ",j+1,i->ifr_name);
		ioctl(sock, SIOCGIFFLAGS,i);
		printf("flags=%d<> ",i->ifr_mtu);
		ioctl(sock, SIOCGIFMTU,i);
		printf("mtu %u\n",i->ifr_ifru.ifru_flags?:65536);

		ioctl(sock, SIOCGIFADDR,i);
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&(i->ifr_addr))->sin_addr.s_addr), buf, sizeof(buf));
		printf("\tinet: %s ", buf);
		ioctl(sock, SIOCGIFNETMASK,i);
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&(i->ifr_netmask))->sin_addr.s_addr), buf, sizeof(buf));
		printf("netmask: %s ", buf);
		ioctl(sock, SIOCGIFBRDADDR,i);
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&(i->ifr_broadaddr))->sin_addr.s_addr), buf, sizeof(buf));
		printf("broadcast: %s\n", buf);

		printf("\n");
	}
    close(sock);
    return 0;
}

static const struct option long_options [] = {
	{ "help",       no_argument,            NULL,           'h' },
    { "interface",    required_argument,            NULL,           'i' },
    { "scan",    no_argument,            NULL,           's' },
    { "addr",    required_argument,            NULL,           'a' },
    { "timeout",    required_argument,            NULL,           't' },
	{ 0, 0, 0, 0 }
};

static void usage(FILE *fp,int argc,char **argv)
{
	fprintf (fp,
		"ARP Test demo\n"
		"Example check whether the IP address is in use\n\n"
		"Usage: %s [options]\n"
        "       %s -a 192.168.0.100 -i ens33 -t 1500\n"
		"Options:\n"
		"-h | --help                        Print this message\n"
        "-i | --interface <interface>       Select network adapter (dafult ens33)\n"
        "-a | --addr <ipaddress>            Destination IP address\n"
        "-s | --scan                        Scan network adapter\n"
        "-t | --timeout <timeout>           Time out (ms) (dafult 1000ms)\n"
        ,argv[0],argv[0]
    );
}

int main(int argc, char **argv)
{
    int socket_fd = -1;
    int ret = -1;
    ARP_PKG_Typedef arp_pkg;
    struct sockaddr_ll peer;
    int addrLen = sizeof(struct sockaddr_ll);
    char interface[8] = "ens33";
    char dst_ip[16] = "255.255.255.255";
    int index;
    int socket_timout_ms = 0;
    struct timeval tv_out;
    struct timeval t_timeout;

    if(argc < 2)
    {
        usage (stdout, argc, argv);
        exit (EXIT_SUCCESS); 
    }
    while((ret = getopt_long (argc, argv,"hi:sa:t:", long_options,&index)) != -1)
    {
        switch (ret) {
            case 0: /* getopt_long() flag */
                break;
            case 'h':
                usage (stdout, argc, argv);
                exit (EXIT_SUCCESS);
                break;
            case 's':
                print_all_net_interface_info();
                exit (EXIT_SUCCESS);
                break;
            case 'i':
                strcpy(interface, optarg);
                break;
            case 'a':
                strcpy(dst_ip, optarg);
                break;
            case 't':
                socket_timout_ms = atoi(optarg);
                gettimeofday(&tv_out, NULL);
                if(socket_timout_ms)
                {
                    t_timeout.tv_sec = tv_out.tv_sec + (socket_timout_ms/1000);
                    t_timeout.tv_usec = tv_out.tv_usec + (socket_timout_ms%1000)*1000;
                }
                else
                {
                    t_timeout.tv_sec = tv_out.tv_sec + 1;
                    t_timeout.tv_usec = tv_out.tv_usec + 0;
                }
                break;
            default:
                usage (stderr, argc, argv);
                exit (EXIT_FAILURE);
                break;
        }
    }

    printf("\nStart arp check...\n");
    printf("ifname:%s dst_ip:%s timeout:%d ms\n\n", interface, dst_ip, socket_timout_ms);

    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(socket_fd < 0)
    {
        perror("socket");
        return -1;
    }

    send_arp(socket_fd, interface, dst_ip);

    // 用以下方法将socket设置为非阻塞方式
    int flags = fcntl(socket_fd, F_GETFL, 0);
    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
    
    // 将非阻塞的设置回阻塞可以用
    // int flags = fcntl(socket, F_GETFL, 0);
    // fcntl(socket, F_SETFL, flags & ~O_NONBLOCK);
    memset(&arp_pkg, 0, sizeof(ARP_PKG_Typedef));
    memset(&peer, 0, sizeof(peer));
    
    while(1)
    {
        ret = recvfrom(socket_fd, &arp_pkg, sizeof(ARP_PKG_Typedef), 0, (struct sockaddr *)&peer, (socklen_t *)&addrLen);
        if (htons(ARPOP_REPLY) == arp_pkg.arp.ea_hdr.ar_op && ret > 0)
        {   
            // 判断源地址是否为冲突的IP地址
            //printf("ARPOP_REPLY\n");
            in_addr_t ip_tmp = inet_addr(dst_ip);
            in_addr_t ip_pkg = *((in_addr_t *)&arp_pkg.arp.arp_spa[0]);

            if (memcmp(&ip_pkg, &ip_tmp, 4) == 0)
            {
                fprintf(stdout, "%d.%d.%d.%d at %02X:%02X:%02X:%02X:%02X:%02X\n", 
                arp_pkg.arp.arp_spa[0], arp_pkg.arp.arp_spa[1], arp_pkg.arp.arp_spa[2], arp_pkg.arp.arp_spa[3],
                arp_pkg.arp.arp_sha[0], arp_pkg.arp.arp_sha[1], arp_pkg.arp.arp_sha[2], 
                arp_pkg.arp.arp_sha[3], arp_pkg.arp.arp_sha[4], arp_pkg.arp.arp_sha[5]);
                // print_sockaddr_ll(&peer);
                // print_arp_pkg(&arp_pkg);
                break;
            }
        }
        gettimeofday(&tv_out, NULL);
        if(tv_out.tv_sec > t_timeout.tv_sec || (tv_out.tv_sec == t_timeout.tv_sec && tv_out.tv_usec > t_timeout.tv_usec))
        {
            printf("timeout!\n");
            break;
        }
        usleep(10*1000);
    }
    close(socket_fd);

    return 0;

}


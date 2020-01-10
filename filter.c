#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define MATCH 1
#define NMATCH 0

//Global Varibles

int enable_flag=1;
unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;
struct iphdr *piphdr;
//Used in Libnetfilter_queue
int fd;
struct nfq_handle *h;
struct nfq_q_handle *qh1;
struct nfq_q_handle *qh2;
struct nfnl_handle *nh;

void display_usage(char *commandname)
{
    printf("Usage1: %s\n",commandname);
    printf("Usage2: %s -x saddr -y daddr -m srcport -n dstport\n",commandname);
}

int getpara(int argc,char *argv[])
{
    
    //get protocol
    if(strncmp(argv[1],"17",2)==0)
        controlled_protocol=17;
    else if(strncmp(argv[1],"0",1)==0)
        controlled_protocol=0;
    else if(strncmp(argv[1],"1",1)==0)
        controlled_protocol=1;
    else if(strncmp(argv[1],"6",1)==0)
        controlled_protocol=6;
    else
    {
        //Normal situation can't come to this
        printf("Unknown protocol!\n");
        exit(1);
    }
    printf("%d\n",controlled_protocol);
    //get source IP
    if(strncmp(argv[2],"0.0.0.0",7)==0)
        controlled_saddr = 0;
    else
    {
        if( inet_aton(argv[2],(struct in_addr *)&controlled_saddr) == 0 )
        {
            printf("Invalid source ip address!\n");
            exit(1);
        }
    }
    //get source port
    unsigned short tmpport;
    tmpport=atoi(argv[3]);
    if(tmpport==0)
    {
        controlled_srcport = 0;
    }
    else
        controlled_srcport=htons(tmpport);
    //get destination IP
    if(strncmp(argv[4],"0.0.0.0",7)==0)
        controlled_daddr = 0;
    else
    {
        if( inet_aton(argv[4],(struct in_addr *)&controlled_daddr) == 0 )
        {
            printf("Invalid destination ip address!\n");
            exit(1);
        }
    }
    //get destination port
    tmpport=atoi(argv[5]);
    if(tmpport==0)
    {
        controlled_dstport = 0;
    }
    else
        controlled_dstport=htons(tmpport);
}

int port_check(unsigned short srcport,unsigned short dstport)
{
    //Control all the port
    if((controlled_srcport==0)&&(controlled_dstport==0))
        return MATCH;
    //Only consider destination port
    if((controlled_srcport!=0)&&(controlled_dstport==0))
    {
        if(controlled_srcport==srcport)
            return MATCH;
        else
            return NMATCH;
    }
    //Only consider destination port
    if((controlled_srcport==0)&&(controlled_dstport!=0))
    {
        if(controlled_dstport==dstport)
            return MATCH;
        else
            return NMATCH;
    }
    if((controlled_srcport!=0)&&(controlled_dstport!=0))
    {
        if((controlled_srcport==srcport)&&(controlled_dstport==dstport))
            return MATCH;
        else
            return NMATCH;
    }
    return NMATCH;
}

int ipaddr_check(unsigned int saddr,unsigned int daddr)
{
    if((controlled_saddr==0)&&(controlled_daddr==0))
        return MATCH;
    if((controlled_saddr!=0)&&(controlled_daddr==0))
    {
        if(controlled_saddr==saddr)
            return MATCH;
        else
            return NMATCH;
    }
    if((controlled_saddr==0)&&(controlled_daddr!=0))
    {
        if(controlled_daddr==daddr)
            return MATCH;
        else
            return NMATCH;
    }
    if((controlled_saddr!=0)&&(controlled_daddr!=0))
    {
        if((controlled_saddr==saddr)&&(controlled_daddr==daddr))
            return MATCH;
        else
            return NMATCH;
    }
    return NMATCH;
}

int icmp_check(void)
{
    struct icmphdr * picmphdr;
    picmphdr=(struct icmphdr *)((char *)piphdr+piphdr->ihl*4);
    if(picmphdr->type==8)
    {
        if(ipaddr_check(piphdr->saddr,piphdr->daddr)==MATCH)
        {
            //printk("An ICMP packet is denied.\n");
            return NF_DROP;
        }
    }
    if(picmphdr->type==0)
    {
        if(ipaddr_check(piphdr->daddr,piphdr->saddr)==MATCH)
        {
            //printk("An ICMP packet is denied.\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

int tcp_check(void)
{
    struct tcphdr *ptcphdr;
    ptcphdr = (struct tcphdr *)((char *)piphdr+piphdr->ihl*4);
    if((ipaddr_check(piphdr->saddr,piphdr->daddr)==MATCH) && port_check(ptcphdr->source,ptcphdr->dest)==MATCH)
    {
        //printk works in kernel mode, is the same as printf
        //printk("A TCP packet is denied!\n");
        return NF_ACCEPT;
    }
    else
        return NF_DROP;
}

int udp_check(void)
{
    struct udphdr *pudphdr;
    pudphdr = (struct udphdr *)((char *)piphdr+piphdr->ihl*4);
    if((ipaddr_check(piphdr->saddr,piphdr->daddr)==MATCH) && port_check(pudphdr->source,pudphdr->dest)==MATCH)
    {
        //printk works in kernel mode, is the same as printf
        //printk("A UDP packet is denied!\n");
        return NF_DROP;
    }
    else
        return NF_ACCEPT;
}

int encrypt(unsigned char *data, int length)
{
    for(int i = 0; i < length; i++)
        data[i] = (unsigned char)((data[i]+128)%256);
}

int decrypt(unsigned char *data, int length)
{
    for(int i = 0; i < length; i++)
        data[i] = (unsigned char)((data[i]+128)%256);
}

unsigned short checksum(unsigned short *buffer, int len, unsigned int temp)
{
    unsigned short *p = buffer;
    unsigned int cs = temp;

    //16bit求和
    while(len >= 2)
    {
	//printf("%x--",*p);
        cs += ntohs(*(p++));
        len -= 2;
    }

    //最后的单字节直接求和
    if(len)
        cs += (*(unsigned char *)p)<<8;

    //高16bit与低16bit求和, 直到高16bit为0
    while(cs>>16)
        cs = (cs>>16) + (cs&0xffff);

    //取反
    return htons((unsigned short)(~cs));
}

static int callback1(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
    int id=0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pdata = NULL;
    int pdata_len;
    int dealmethod=NF_DROP;
    char srcstr[32],deststr[32];
    ph= nfq_get_msg_packet_hdr(nfa);
    if(ph==NULL)
        return 1;
    id=ntohl(ph->packet_id);
    //If firewall is disabled, let packets pass
    if(enable_flag==0)
        return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
    //Get packet from IP layer
    pdata_len = nfq_get_payload(nfa,&pdata);
    if(pdata!=NULL)
        piphdr = (struct iphdr *) pdata;
    else
        return 1;
    inet_ntop(AF_INET,&(piphdr->saddr),srcstr,32);
    inet_ntop(AF_INET,&(piphdr->daddr),deststr,32);
    //printf("get a packet:%s -> %s",srcstr,deststr);
    if(piphdr->protocol==controlled_protocol)
    {
        //ICMP
        if(piphdr->protocol==1)
            dealmethod=icmp_check();
        else{
            //TCP
            if(piphdr->protocol==6)
            {
                dealmethod=tcp_check();
                if(dealmethod == NF_ACCEPT)
                {
                    struct tcphdr *ptcphdr;
                    ptcphdr = (struct tcphdr *)((char *)piphdr+piphdr->ihl*4);
                    if((pdata_len-piphdr->ihl*4) == ptcphdr->doff*4)
                        return nfq_set_verdict(qh,id,dealmethod,0,NULL);
                    else
                    {
                        unsigned char *ptcpdata;
                        ptcpdata = (unsigned char *)ptcphdr+ptcphdr->doff*4;
                        decrypt(ptcpdata, pdata_len-piphdr->ihl*4-ptcphdr->doff*4);
                        ptcphdr->check = 0;
                        unsigned int temp = ntohs(piphdr->saddr>>16) + ntohs(piphdr->saddr&0xffff) + ntohs(piphdr->daddr>>16) + ntohs(piphdr->daddr&0xffff) + pdata_len - piphdr->ihl*4 + 6;
			
                        ptcphdr->check = checksum((unsigned short *)ptcphdr, pdata_len - piphdr->ihl*4, temp);
			
                        return nfq_set_verdict(qh,id,dealmethod,pdata_len,pdata);
                    }
                }
            }
            else{
                //UDP
                if(piphdr->protocol==17)
                    dealmethod=udp_check();
                else{
                    printf("Can't recognize packet's type");
                    exit(1);
                }
            }
        }
    }
    else
        dealmethod=NF_ACCEPT;
    return nfq_set_verdict(qh,id,dealmethod,0,NULL);
}

static int callback2(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
    int id=0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pdata = NULL;
    int pdata_len;
    int dealmethod=NF_DROP;
    char srcstr[32],deststr[32];
    ph= nfq_get_msg_packet_hdr(nfa);
    if(ph==NULL)
        return 1;
    id=ntohl(ph->packet_id);
    //If firewall is disabled, let packets pass
    if(enable_flag==0)
        return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
    //Get packet from IP layer
    pdata_len = nfq_get_payload(nfa,&pdata);
    if(pdata!=NULL)
        piphdr = (struct iphdr *) pdata;
    else
        return 1;
    inet_ntop(AF_INET,&(piphdr->saddr),srcstr,32);
    inet_ntop(AF_INET,&(piphdr->daddr),deststr,32);
    //printf("get a packet:%s -> %s",srcstr,deststr);
    if(piphdr->protocol==controlled_protocol)
    {
        //ICMP
        if(piphdr->protocol==1)
            dealmethod=icmp_check();
        else{
            //TCP
            if(piphdr->protocol==6)
            {
                dealmethod=tcp_check();
                if(dealmethod == NF_ACCEPT)
                {
                    struct tcphdr *ptcphdr;
                    ptcphdr = (struct tcphdr *)((char *)piphdr+piphdr->ihl*4);
                    if((pdata_len-piphdr->ihl*4) == ptcphdr->doff*4)
                        return nfq_set_verdict(qh,id,dealmethod,0,NULL);
                    else
                    {
                        unsigned char *ptcpdata;
                        ptcpdata = (unsigned char *)ptcphdr+ptcphdr->doff*4;
                        encrypt(ptcpdata, pdata_len-piphdr->ihl*4-ptcphdr->doff*4);
                        ptcphdr->check = 0;
			
                        unsigned int temp = ntohs(piphdr->saddr>>16) + ntohs(piphdr->saddr&0xffff) + ntohs(piphdr->daddr>>16) + ntohs(piphdr->daddr&0xffff) + pdata_len - piphdr->ihl*4 + 6;


                        ptcphdr->check = checksum((unsigned short *)ptcphdr, pdata_len - piphdr->ihl*4, temp);
			//printf("%x\n\n",ptcphdr->check);
                        return nfq_set_verdict(qh,id,dealmethod,pdata_len,pdata);
                    }
                }
            }
            else{
                //UDP
                if(piphdr->protocol==17)
                    dealmethod=udp_check();
                else{
                    printf("Can't recognize packet's type");
                    exit(1);
                }
            }
        }
    }
    else
        dealmethod=NF_ACCEPT;
    return nfq_set_verdict(qh,id,dealmethod,0,NULL);
}

int main(int argc, char **argv){
    char buf[1600];
    int length;
    //In this mode all packets will pass
    if(argc==1)
        enable_flag==0;
    else
        getpara(argc,argv); 
    h = nfq_open();
    if(!h)
    {
        fprintf(stderr,"Error during nfq_open.\n");
        exit(1);
    }
    //Eliminate existing bind to nf_queue handle.
    if(nfq_unbind_pf(h,AF_INET)<0)
    {
        fprintf(stderr,"Error during nfq_unbind.\n");
        exit(1);
    }
    if(nfq_bind_pf(h,AF_INET)<0)
    {
        fprintf(stderr,"Error during nfq_bind.\n");
        exit(1);
    }
    qh1 = nfq_create_queue(h,1,&callback1,NULL);
    if(!qh1)
    {
        fprintf(stderr,"Error during nfq_creat.\n");
        exit(1);
    }
    qh2 = nfq_create_queue(h,2,&callback2,NULL);
    if(!qh2)
    {
        fprintf(stderr,"Error during nfq_creat.\n");
        exit(1);
    }
    //NFQNL_COPY_PACKET means return packets
    if(nfq_set_mode(qh1,NFQNL_COPY_PACKET,0xffff)<0)
    {
        fprintf(stderr,"Error during nfq_set_mode.\n");
    }
    if(nfq_set_mode(qh2,NFQNL_COPY_PACKET,0xffff)<0)
    {
        fprintf(stderr,"Error during nfq_set_mode.\n");
    }
    nh=nfq_nfnlh(h);
    fd=nfnl_fd(nh);
    while(1)
    {
        memset(buf,0,1600);
        length=recv(fd,buf,1600,0);  //receive data packets
        nfq_handle_packet(h,buf,length); //Call callback function to process packets,then send packet.
    }
    nfq_destroy_queue(qh1);
    nfq_destroy_queue(qh2);
    nfq_close(h);
    exit(0);
}

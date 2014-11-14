#include "espmissingincludes.h"
#include "user_interface.h"
#include "mem.h"
#include "osapi.h"
#include "dnsserver.h"

static struct espconn ptrespconn;
static esp_udp ptrespudp;

#define htons16(i) ((i>>8) | (i<<8))

#define FLAG_QR 1 << 7
#define FLAG_TC 1 << 2

struct dnsheader {
    uint16 id;
    uint8 flags[2];
    
    /*
    uint8  qr :1;
    uint8  opcode :4;
    uint8  aa :1;
    uint8  tc :1;
    uint8  rd :1;

    uint8  ra :1;
    uint8  z  :3;
    uint8  rcode :4;
    */

    uint16 qdcount;
    uint16 ancount;
    uint16 nscount;
    uint16 arcount;
};

struct dnsquestion {
    // QNAME
    uint16 qtype;
    uint16 qclass;
};

struct dnsanswer {
    // NAME
    uint8 name[2];
    uint16 type;
    uint16 class;
    uint32 ttl;
    uint16 rdlength;
    // RDATA
} __attribute__((packed));

#define QTYPE_A  0x0001
#define QTYPE_NS 0x0002
#define QTYPE_MX 0x000f

/*
 * That is one of these moments, when I feel I just shouldn't have been born.
 */
LOCAL void ICACHE_FLASH_ATTR
dnsserver_recv(void* arg, char *pusrdata, unsigned short length)
{
    uint8 respbuf[1024];
    uint8 ansbuf[1024];

    unsigned short resplen = 0, anslen = 0;

    struct dnsheader* header = (struct dnsheader*) pusrdata;
    header->id = htons16(header->id);
    header->qdcount = htons16(header->qdcount);
    header->ancount = htons16(header->ancount);
    header->nscount = htons16(header->nscount);
    header->arcount = htons16(header->arcount);
    
    os_printf("dns request id=0x%04X qdcount=%d, ancount=%d, nscount=%d, arcount=%d\n",
            header->id, header->qdcount, header->ancount, header->nscount, header->arcount);

    if(header->flags[0] & FLAG_TC)
    {
        os_printf("truncated, escaping\n");
        return;
    }

    if(header->flags[0] & FLAG_QR)
    {
        os_printf("q response, escaping\n");
        return;
    }

    char* qptr = pusrdata+sizeof(struct dnsheader);
    for(int i = 0 ; i < header->qdcount; i++)
    {
        struct dnsanswer answer; // = (struct dnsanswer*) ansbuf;
        answer.name[0] = 0xc0 | ((qptr-pusrdata) >> 8);
        answer.name[1] = ((qptr-pusrdata) & 0xff);

        os_printf("query %d: ", i);
        while(*qptr != 0) {
            for(int c = 0; c < *qptr; c++)
                os_printf("%c", *(qptr+c+1));
            qptr += (*qptr+1);
            os_printf(".");
        }
        qptr++;
        
        // rather dirty hack, because unaligned memory access causes exceptions
        struct dnsquestion question; // = (struct dnsquestion*) qptr;
        os_memcpy(&question, qptr, sizeof(struct dnsquestion));

        answer.type = question.qtype;
        answer.class = question.qclass;
        answer.ttl = 1; // ?
        answer.rdlength = htons16(4);
        
        os_memcpy(ansbuf+anslen, &answer, sizeof(struct dnsanswer));
        anslen += sizeof(struct dnsanswer);
        
        // yay for hardcoded IPs...
        ansbuf[anslen++] = 192;
        ansbuf[anslen++] = 168;
        ansbuf[anslen++] = 4;
        ansbuf[anslen++] = 1;

        // something gets fucked up with htons16 but we don't care, really...
        os_printf(" qtype=%04X qclass=%04X\n", htons16(question.qtype), htons16(question.qclass));
        qptr += sizeof(struct dnsquestion);
    }
    
    struct dnsheader* respheader = (struct dnsheader*) respbuf;
    
    resplen += qptr-pusrdata;
    if(resplen+anslen > 1024) {
        os_printf("whoopsie, buf too small\n");
        return;
    }

    // copy header and questions part
    os_memcpy(respbuf,
              pusrdata,
              qptr-pusrdata);

    
    respheader->flags[0] = FLAG_QR;
    respheader->flags[1] = 0;

    respheader->id = htons16(header->id);           //
    respheader->qdcount = htons16(header->qdcount); // flip bytes
    respheader->ancount = htons16(header->qdcount); //
    respheader->nscount = 0;
    respheader->arcount = 0;

    os_memcpy(respbuf+resplen,
              ansbuf,
              anslen);

    resplen += anslen;
    
    // TODO TCP support?
    espconn_sent(&ptrespconn, respbuf, resplen);
}

void ICACHE_FLASH_ATTR
dnsserver_init(void)
{
    ptrespconn.type = ESPCONN_UDP;
    ptrespconn.proto.udp = &ptrespudp;
    ptrespconn.proto.udp->local_port = 53;
    espconn_regist_recvcb(&ptrespconn, dnsserver_recv);
    espconn_create(&ptrespconn);
}

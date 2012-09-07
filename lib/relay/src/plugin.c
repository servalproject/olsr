

/*
 Simple payload relay between an olsr network and a local UDP port.

 example configuration;
 LoadPlugin "name..."{
   PlParam  "BindPort"	"1000" 
   PlParam  "DestPort"	"1001"
   PlParam  "MagicNumber" "123"
 }
 
 Incoming packets should be preceeded with the following header;
   u_int8_t magicNumber;
   u_int8_t ttl;
 
 Outgoing packets will be preceeded with the following header;
   u_int8_t magicNumber;
   u_int8_t ttl;
   u_int8_t addr_len; // 4 / 16
   u_int8_t originator[addr_len];
   
 Payload MTU is at least 12 bytes less than the MTU of the outgoing interface.
 
 Since olsr packs multiple messages together, only sending one message per packet 
 should allow reasonably efficient network usage across the entire mesh.
 */

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include "plugin_util.h"
#include "olsr_protocol.h"
#include "ipcalc.h"
#include "link_set.h"
#include "olsr.h"
#include "net_olsr.h"
#include "plugin.h"
#include "parser.h"

#define MESSAGE_TYPE 140

int bindPort=-1;
int destPort=-1;
int udpSocket=-1;
int magicNumber;

struct payload_header{
  u_int8_t magicNumber;
  u_int8_t ttl;
  u_int8_t addr_len;
};

// add additional headers with originator info and send the data packet
static void relay_packet(unsigned char *buff, int size, int ttl, void *addr, int addr_size){
  
  struct sockaddr_in sockaddr={
    .sin_family=AF_INET,
    .sin_addr.s_addr=htonl(INADDR_LOOPBACK),
    .sin_port=htons(destPort),
  };
  
  struct payload_header hdr={
    .magicNumber = magicNumber,
    .ttl = ttl,
    .addr_len = addr_size,
  };
  
  struct iovec iov[]={
    {
      .iov_base=&hdr,
      .iov_len=sizeof(hdr),
    },
    {
      .iov_base=addr,
      .iov_len=addr_size,
    },
    {
      .iov_base=buff,
      .iov_len=size,
    },
  };
  
  struct msghdr msg={
    .msg_name=&sockaddr,
    .msg_namelen=sizeof(struct sockaddr_in),
    .msg_iov=iov,
    .msg_iovlen=3,
  };
  
  fprintf(stderr, "Relaying message\n");
  if (sendmsg(udpSocket, &msg, 0)<0){
    perror("Sending packet");
  }
}

// parse an incoming message
static bool
olsr_parser(union olsr_message *message, struct interface *in_if __attribute__ ((unused)), union olsr_ip_addr *ipaddr)
{
  union olsr_ip_addr *originator;
  int ttl;
  int seqno;
  int size;
  int padding;
  unsigned char *buff;
  
  if (olsr_cnf->ip_version == AF_INET) {
    ttl = message->v4.ttl;
    seqno = message->v4.seqno;
    originator = (union olsr_ip_addr *)&message->v4.originator;
    size = ntohs(message->v4.olsr_msgsize) - (sizeof(struct olsrmsg) - sizeof(message->v4.message));
    buff = (unsigned char *)&message->v4.message;
  } else {
    ttl = message->v6.ttl;
    seqno = message->v6.seqno;
    originator = (union olsr_ip_addr *)&message->v6.originator;
    size = ntohs(message->v6.olsr_msgsize) - (sizeof(struct olsrmsg6) - sizeof(message->v6.message));
    buff = (unsigned char *)&message->v6.message;
  }
  
  /* Ignore if we sent it */
  if (ipequal(originator, &olsr_cnf->main_addr)){
    fprintf(stderr, "Ignoring message from myself\n");
    return false;
  }
  
  /* Ignore if the neighbor is not symmetric. */
  if (check_neighbor_link(ipaddr) != SYM_LINK){
    fprintf(stderr, "Ignoring message from non-peer\n");
    return false;
  }

  padding = buff[0];
  relay_packet(buff +1, size - 1 - padding, ttl, originator, olsr_cnf->ipsize);
  
  // forward the message
  return true;
}

// send a packet
static int
olsr_send(unsigned char *buff, int len, int ttl)
{
  char buffer[len + sizeof(union olsr_message)];
  int aligned_size;
  union olsr_message *message = (union olsr_message *)buffer;
  struct interface *ifn;
  int padding=0;
  unsigned char *dest;
  
  aligned_size=len+1;
  
  if (olsr_cnf->ip_version == AF_INET) {
    aligned_size+=sizeof(struct olsrmsg) - sizeof(message->v4.message);
    
    if ((aligned_size % 4)){
      padding = 4 - (aligned_size % 4);
      aligned_size += padding;
    }
    
    memset(message, 0, aligned_size);
   
    message->v4.olsr_msgtype = MESSAGE_TYPE;
    message->v4.olsr_vtime = reltime_to_me(10 * MSEC_PER_SEC);
    memcpy(&message->v4.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
    message->v4.ttl = ttl;
    message->v4.hopcnt = 0;
    message->v4.seqno = htons(get_msg_seqno());
    message->v4.olsr_msgsize = htons(aligned_size);
    
    dest = (unsigned char *)&message->v4.message;
    
  } else {
    aligned_size+=sizeof(struct olsrmsg6) - sizeof(message->v6.message);
    
    if ((aligned_size % 4)){
      padding = 4 - (aligned_size % 4);
      aligned_size += padding;
    }
    
    memset(message, 0, aligned_size);
    
    message->v6.olsr_msgtype = MESSAGE_TYPE;
    message->v6.olsr_vtime = reltime_to_me(10 * MSEC_PER_SEC);
    memcpy(&message->v6.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
    message->v6.ttl = ttl;
    message->v6.hopcnt = 0;
    message->v6.seqno = htons(get_msg_seqno());
    message->v6.olsr_msgsize = htons(aligned_size);
    
    dest = (unsigned char *)&message->v6.message;
  }
  
  dest[0]=padding;
  memcpy(dest +1, buff, len);
  
  for (ifn = ifnet; ifn; ifn = ifn->int_next) {
    if (net_outbuffer_push(ifn, message, aligned_size) != aligned_size) {
      /* out buffer full, send a packet and try again */
      net_output(ifn);
      if (net_outbuffer_push(ifn, message, aligned_size) != aligned_size) {
	fprintf(stderr, "Failed to pushing outgoing payload to interface %s\n", ifn->int_name);
      }
    }
  }
  
  return 0;
}

static void
read_socket(int fd, void *data __attribute__ ((unused)), unsigned int flags __attribute__ ((unused)))
{
  unsigned char buff[1600];
  struct sockaddr_in addr;
  socklen_t size = sizeof(struct sockaddr_in);
  
  int msg_len = recvfrom(fd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &size);
  if (msg_len<3){
    fprintf(stderr, "Received message is only %d bytes long\n",msg_len);
    return;
  }
  
  // drop packets from other port numbers
  if (ntohs(addr.sin_port)!=destPort){
    fprintf(stderr, "Received message came from the wrong port %d\n",ntohs(addr.sin_port));
    return;
  }
  
  if ((magicNumber & 0xFF) != buff[0]){
    fprintf(stderr, "Magic number header doesn't match %d\n",buff[0]);
    return;
  }

  olsr_send(buff+2, msg_len-2, buff[1]);
}

int
olsrd_plugin_interface_version(void)
{
  return PLUGIN_INTERFACE_VERSION;
}

int
olsrd_plugin_init(void)
{
  int fd;
  int reuseP = 1;
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    .sin_port = htons(bindPort),
  };
  
  olsr_parser_add_function(&olsr_parser, MESSAGE_TYPE);
  
  fd = socket(PF_INET,SOCK_DGRAM,0);
  if (fd < 0) {
    perror("Error creating socket");
    return -1;
  } 
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof(reuseP)) < 0) {
    perror("setsockopt(SO_REUSEADR)");
    close(fd);
    return -1;
  }
  
#ifdef SO_REUSEPORT
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseP, sizeof(reuseP)) < 0) {
    perror("setsockopt(SO_REUSEPORT)");
    close(fd);
    return -1;
  }
#endif
  
  /* Automatically close socket on calls to exec().
   This makes life easier when we restart with an exec after receiving
   a bad signal. */
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, NULL) | O_CLOEXEC);
  
  if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
    perror("Bind failed");
    fprintf(stderr, "%x %d, error %d\n", addr.sin_addr.s_addr, addr.sin_port, errno);
    close(fd);
    return -1;
  }

  udpSocket=fd;
  // tell olsr we want to read data from this socket as soon as it arrives for low latency
  add_olsr_socket(fd, NULL, &read_socket, NULL, SP_IMM_READ);
  
  printf("Bount socket for relaying packets on ports %d-%d\n",bindPort,destPort);
  return 1;
}

static const struct olsrd_plugin_parameters plugin_parameters[] = {
  {.name = "BindPort", .set_plugin_parameter = &set_plugin_port, .data = &bindPort},
  {.name = "DestPort", .set_plugin_parameter = &set_plugin_port, .data = &destPort},
  {.name = "MagicNumber", .set_plugin_parameter = &set_plugin_int, .data = &magicNumber},
};

void
olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params, int *size)
{
  *params = plugin_parameters;
  *size = ARRAYSIZE(plugin_parameters);
}

void
olsr_plugin_exit(void)
{
  close(udpSocket);
}

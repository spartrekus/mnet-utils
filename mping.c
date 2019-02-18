
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;
struct sockaddr_in dest_addr;
pid_t pid;
struct sockaddr_in from;
struct timeval tvrecv;
void statistics(int signo);
unsigned short cal_chksum(unsigned short *addr, int len);
int pack(int pack_no);
void send_packet(void);
void recv_packet(void);
int unpack(char *buf, int len);
void tv_sub(struct timeval *out, struct timeval *in);




u_short in_cksum(u_short *addr, int len);


struct hostdesc {
	char *hostname;
	struct in_addr hostaddr;
	struct hostdesc *next;
};

struct hostdesc *hostnames;
struct hostdesc *hosttail;

void resolv_from(char *hostfrom, struct in_addr *fromaddr)
{
	struct hostent *hp;
	if (hostfrom == NULL) {
		fromaddr->s_addr = 0;
		return;
	}
	
	if ((hp = gethostbyname(hostfrom)) == NULL) {
		if ((fromaddr->s_addr = inet_addr(hostfrom)) == -1) {
			fprintf(stderr, "could not resolve from address\n");
			exit(0);
		}
	} else {
		bcopy(hp->h_addr_list[0], &fromaddr->s_addr, hp->h_length);
	}
}


int makehosts(char **hostlist)
{
	int i;
	struct hostent *hp;
	struct in_addr tmpaddr;
	int hostcount = 0;
	
	for (i = 0; hostlist[i]; i++) {
#ifdef DEBUG
		printf("Resolving %s\n", hostlist[i]);
#endif
		if ((hp = gethostbyname(hostlist[i])) == NULL) {
			if ((tmpaddr.s_addr = inet_addr(hostlist[i]))) {
				/* Could not resolve it.  Skip it. */
				fprintf(stderr, "%s: unknown host\n",
					hostlist[i]);
				continue;
			}
		} else {
			bcopy(hp->h_addr_list[0],
			      &tmpaddr.s_addr, hp->h_length);
		}

		/* The host has been resolved.  Put it in the chain */
		/* We want to stick it on the end. */
		if (hostnames == NULL) {
			hostnames = (struct hostdesc *)
				malloc(sizeof(*hostnames));
			if (hostnames == NULL) {
				perror("hostnames malloc failed");
				exit(-1);
			}
			hosttail = hostnames;
		} else {
			hosttail->next = (struct hostdesc *)
				malloc(sizeof(*hostnames));
			if (hosttail->next == NULL) {
				perror("hosttail->next malloc failed");
				exit(-1);
			}
			hosttail = hosttail->next;
		}
		hosttail->hostname = strdup(hostlist[i]);
		if (hosttail->hostname == NULL) {
			perror("strdup failed");
			exit(-1);
		}
		hosttail->hostaddr = tmpaddr;
		hosttail->next = NULL;
		hostcount++;
	}
	return hostcount;
}




void usage(char *prog)
{
   fprintf(stderr,
	   "%s  <-query> [-B] [-f fromhost] [-d delay] [-T time] targets\n"
	   "    where <query> is one of:\n"
	   "        -t : icmp timestamp request (default)\n"
	   "        -m : icmp address mask request\n"
	   "    The delay is in microseconds to sleep between packets.\n"
	   "    targets is a list of hostnames or addresses\n"
	   "    -T specifies the number of seconds to wait for a host to\n"
	   "       respond.  The default is 5.\n"
	   "    -B specifies \'broadcast\' mode.  icmpquery will wait\n"
	   "       for timeout seconds and print all responses.\n"
	   "    If you're on a modem, you may wish to use a larger -d and -T\n"
	   ,prog);
}




/*
 * Set up a packet.  Returns the length of the ICMP portion.
 */

int initpacket(char *buf, int querytype, struct in_addr fromaddr)
{
   struct ip *ip = (struct ip *)buf;
   struct icmp *icmp = (struct icmp *)(ip + 1);

   /* things we customize */
   int icmplen = 0;

   ip->ip_src = fromaddr;	/* if 0,  have kernel fill in */
   ip->ip_v = 4;		/* Always use ipv4 for now */
   ip->ip_hl = sizeof *ip >> 2;
   ip->ip_tos = 0;
   ip->ip_id = htons(4321);
   ip->ip_ttl = 255;
   ip->ip_p = 1;
   ip->ip_sum = 0;                 /* kernel fills in */

   icmp->icmp_seq = 1;
   icmp->icmp_cksum = 0;
   icmp->icmp_type = querytype;
   icmp->icmp_code = 0;

   switch(querytype) {
   case ICMP_TSTAMP:
	   gettimeofday( (struct timeval *)(icmp+8), NULL);
	   bzero( icmp+12, 8);
	   icmplen = 20;
	   break;
   case ICMP_MASKREQ:
	   *((char *)(icmp+8)) = 255;
	   icmplen = 12;
	   break;
   default:
	   fprintf(stderr, "eek: unknown query type\n");
	   exit(0);
   }
   ip->ip_len = sizeof(struct ip) + icmplen;
   return icmplen;
}
   
void sendpings(int s, int querytype, struct hostdesc *head, int delay,
	       struct in_addr fromaddr)
     
{
	char buf[1500];
	struct ip *ip = (struct ip *)buf;
	struct icmp *icmp = (struct icmp *)(ip + 1);
	struct sockaddr_in dst;
	int icmplen;

	bzero(buf, 1500);
	icmplen = initpacket(buf, querytype, fromaddr);
	dst.sin_family = AF_INET;

	while (head != NULL) {
#ifdef DEBUG
		printf("pinging %s\n", head->hostname);
#endif
		ip->ip_dst.s_addr = head->hostaddr.s_addr;
		dst.sin_addr = head->hostaddr;
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = in_cksum((u_short *)icmp, icmplen);
		if (sendto(s, buf, ip->ip_len, 0,
			   (struct sockaddr *)&dst,
			   sizeof(dst)) < 0) {
			perror("sendto");
		}
		if (delay)
			usleep(delay);
		/* Don't flood the pipeline..kind of arbitrary */
		head = head->next;
	}
}

void myexit(int whatsig)
{
	exit(0);
}

/*
 * Listen for 'hostcount' pings, print out the information, and
 * then exit.
 */

void recvpings(int s, int querytype, struct hostdesc *head, int hostcount,
	       int broadcast)
{
	char buf[1500];
	struct ip *ip = (struct ip *)buf;
	struct icmp *icmp;
	int err = 0;
	long int fromlen = 0;
	int hlen;
	struct timeval tv;
	struct tm *tmtime;
	int recvd = 0;
	char *hostto;
	char hostbuf[128], timebuf[128];
	struct hostdesc *foundhost;
	unsigned long int icmptime, icmpmask;

	gettimeofday(&tv, NULL);

	while (recvd < hostcount) {
		if ((err = recvfrom(s, buf, sizeof buf, 0, NULL,
				    (int *)&fromlen)) < 0)
		{
			perror("icmpquery:  recvfrom");
		}
      
		hlen = ip->ip_hl << 2;
		icmp = (struct icmp *)(buf + hlen);

		/* Find the host */
		hostto = 0;
		for (foundhost = head; foundhost != NULL;
		     foundhost = foundhost->next) {
			if (foundhost->hostaddr.s_addr == ip->ip_src.s_addr) {
				hostto = foundhost->hostname;
				break;
			}
		}

		if (!hostto) {
			sprintf(hostbuf, "unknown (%s)",
				inet_ntoa(ip->ip_src));
			hostto = hostbuf;
		}
		
		/* For time */
		switch(icmp->icmp_type) {
		case ICMP_TSTAMPREPLY:
			icmptime = ntohl(icmp->icmp_ttime);
			 /* ms since midnight. yuch. */
			tv.tv_sec -= tv.tv_sec%(24*60*60);
			tv.tv_sec += (icmptime/1000);
			tv.tv_usec = (icmptime%1000);
			tmtime = localtime(&tv.tv_sec);
			strftime(timebuf, 128, "%H:%M:%S", tmtime);
			printf("%-40.40s:  %s\n", hostto, timebuf);
			break;

		case ICMP_MASKREPLY:
			icmpmask = ntohl(icmp->icmp_dun.id_mask);
			printf("%-40.40s:  0x%lX\n", hostto, icmpmask);
			break;

		default:
			printf("Unknown ICMP message received (type %d)\n",
			       icmp->icmp_type);
			break;
		}
		if (!broadcast)
			recvd++;
	}
}




/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 *      From FreeBSD's ping.c
 */

u_short
in_cksum(addr, len)
	u_short *addr;
	int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}







void statistics(int signo) {
	printf("\n--------------------PING statistics-------------------\n");
	printf("%d packets transmitted, %d received , %%%d lost\n", nsend,
			nreceived, (nsend - nreceived) / nsend * 100);
	close(sockfd);
	exit(1);
}
unsigned short cal_chksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(unsigned char*) (&answer) = *(unsigned char*) w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}
int pack(int pack_no)

{
	int i, packsize;
	struct icmp *icmp;
	struct timeval *tval;
	icmp = (struct icmp*) sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = pack_no;
	icmp->icmp_id = pid;
	packsize = 8 + datalen;
	tval = (struct timeval*) icmp->icmp_data;
	gettimeofday(tval, NULL);
	icmp->icmp_cksum = cal_chksum((unsigned short*) icmp, packsize);
	return packsize;
}

void send_packet()
{
	int packetsize;
	while (nsend < MAX_NO_PACKETS)
	{
		nsend++;
		packetsize = pack(nsend);
		if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*)
		&dest_addr, sizeof(dest_addr)) < 0)
		{
			perror("sendto error");
			continue;
		}
		sleep(1);
	}
}

void recv_packet()
{
	int n, fromlen;
	extern int errno;
	signal(SIGALRM, statistics);
	fromlen = sizeof(from);
	while (nreceived < nsend)
	{
		alarm(MAX_WAIT_TIME);
		if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct
		sockaddr*) &from, &fromlen)) < 0)
		{
			if (errno == EINTR)
				continue;
			perror("recvfrom error");
			continue;
		}
		gettimeofday(&tvrecv, NULL);
		if (unpack(recvpacket, n) == -1)
			continue;
		nreceived++;
	}
}
int unpack(char *buf, int len)
{
int i, iphdrlen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;
	ip = (struct ip*) buf;
	iphdrlen = ip->ip_hl << 2;
	icmp = (struct icmp*) (buf + iphdrlen);
	len -= iphdrlen;
	if (len < 8)
	{
		printf("ICMP packets\'s length is less than 8\n");
		return -1;
	}
	if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
	{
		tvsend = (struct timeval*) icmp->icmp_data;
		tv_sub(&tvrecv, tvsend);
		rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;
		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n", len,
		inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
	}
	else
		return -1;
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}





/*
int  main(int argc, char *argv[])
{
	struct hostent *host;
	struct protoent *protocol;
	unsigned long inaddr = 0l;
	int waittime = MAX_WAIT_TIME;
	int size = 50 * 1024;
	if (argc < 2)
	{
		printf("usage:%s hostname/IP address\n", argv[0]);
		exit(1);
	}
	if ((protocol = getprotobyname("icmp")) == NULL)
	{
		perror("getprotobyname");
		exit(1);
	}
	if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
	{
		perror("socket error");
		exit(1);
	}
	setuid(getuid());
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	bzero(&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	if (inaddr = inet_addr(argv[1]) == INADDR_NONE)
	{
		if ((host = gethostbyname(argv[1])) == NULL)
		{
			perror("gethostbyname error");
			exit(1);
		}
		memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);
	}
	else
	dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
	pid = getpid();
	printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa
	(dest_addr.sin_addr), datalen);
	send_packet();
	recv_packet();
	statistics(SIGALRM);
	return 0;
}
*/

int main(int argc, char **argv)
{

	struct hostent *host;
	struct protoent *protocol;
	unsigned long inaddr = 0l;
	int waittime = MAX_WAIT_TIME;
	int size = 50 * 1024;
	if (argc < 2)
	{
		printf("usage:%s hostname/IP address\n", argv[0]);
		exit(1);
	}
	if ((protocol = getprotobyname("icmp")) == NULL)
	{
		perror("getprotobyname");
		exit(1);
	}
	if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
	{
		perror("socket error");
		exit(1);
	}
	setuid(getuid());
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	bzero(&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	if (inaddr = inet_addr(argv[1]) == INADDR_NONE)
	{
		if ((host = gethostbyname(argv[1])) == NULL)
		{
			perror("gethostbyname error");
			exit(1);
		}
		memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);
	}
	else
	dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
	pid = getpid();
	printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa
	(dest_addr.sin_addr), datalen);
	send_packet();
	recv_packet();
	statistics(SIGALRM);
	return 0;




   // imt
   int s;
   char *progname;
   extern char *optarg;         /* getopt variable declarations */
   char *hostfrom = NULL;
   extern int optind;
   extern int optopt;
   extern int opterr;
   char ch;                     /* Holds the getopt result */
   int on = 1;
   int hostcount;
   int delay = 0;
   int querytype = ICMP_TSTAMP;
   struct in_addr fromaddr;
   int timeout = 5;  /* Default to 5 seconds */
   int broadcast = 0; /* Should we wait for all responses? */

   fromaddr.s_addr = 0;

   progname = argv[0];

   while ((ch = getopt(argc, argv, "Btmf:d:T:")) != EOF) 
      switch(ch)
      {
      case 'B':
	      broadcast = 1;
	      break;
      case 'd':
	      delay = (int) strtol(optarg, NULL, 10);
	      break;
      case 't': /* timestamp request */
	      querytype = ICMP_TSTAMP;
	      break;
      case 'm': /* address mask request */
	      querytype = ICMP_MASKREQ;
	      break;
      case 'f':
	      hostfrom = optarg;
	      resolv_from(hostfrom, &fromaddr);
	      break;
      case 'T':
	      timeout = (int) strtol(optarg, NULL, 10);
	      break;
      default:
	      usage(progname);
	      exit(-1);
      }
   argc -= optind;
   argv += optind;

   if (!argv[0] || !strlen(argv[0])) 
   {
      usage(progname);
      exit(-1);
   }

   hostcount = makehosts(argv);

   if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
      perror("socket");
      exit(1);
   }
   if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
      perror("IP_HDRINCL");
      exit(1);
   }

   signal(SIGALRM, myexit);
   alarm(timeout);
   sendpings(s, querytype, hostnames, delay, fromaddr);
   recvpings(s, querytype, hostnames, hostcount, broadcast);
   exit(0);
}
   



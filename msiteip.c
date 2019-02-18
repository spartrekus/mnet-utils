
#include <stdio.h>
#define PATH_MAX 2500
#if defined(__linux__) //linux
#define MYOS 1
#elif defined(_WIN32)
#define MYOS 2
#elif defined(_WIN64)
#define MYOS 3
#elif defined(__unix__) 
#define MYOS 4  // freebsd
#define PATH_MAX 2500
#else
#define MYOS 0
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <time.h>


 #include <stdio.h>
 #include <signal.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netdb.h>
 #include <netinet/in.h>
 #include <unistd.h>
 #include <string.h>
 #include <stdlib.h>
 #include <arpa/inet.h>
 #include <errno.h>
 #include <assert.h>

int main(int argc, char **argv) 
{

     if (argc < 2) {
         fprintf(stderr, "usage: %s domain_name\nE.g. %s www.yahoo.com/lalal.html\n", argv[0], argv[0]);
         return(0);
     }

 struct protoent *pr;
 struct in_addr inp;
 int x = 1;
 int ret;
 char buf[4192];
 char ip[16];
 struct hostent *host;
 int sock, bytes_recieved;
 struct sockaddr_in server_addr;

 char url[strlen(argv[1])];
 strcpy(url,argv[1]);
 char *index_page = strstr (argv[1] , "/");
 char *host_name = strtok(url,"/");

 printf("url %s\n",url);
 printf("index %s\n",index_page);
 printf("host %s\n",host_name);

 char message[4000];
 sprintf(message,"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",index_page,host_name);
 printf("%s",message);

 host = gethostbyname(host_name);
 if (host != NULL) {
     memcpy(&inp, host->h_addr_list[0], host->h_length);
     sprintf(ip, "%s", inet_ntoa(inp));
 }
 else {
     printf("ERROR - Host ip was not found.\n\n");
     exit(1);
 }

 printf("%s\n",ip);

 pr = getprotobyname("tcp");
 if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
     perror("Socket");
     exit(1);
 }
 printf("%s\n",message);
 server_addr.sin_family = AF_INET;    
 server_addr.sin_port = htons(80);  
 server_addr.sin_addr = *((struct in_addr *)host->h_addr);
 bzero(&(server_addr.sin_zero),8);

 if (connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
     perror("Connect");
     exit(1);
 }

 write(sock, message, strlen(message));

  //while ((ret = read(sock, buf, 4192)) != 0) 
  {
  //   buf[ret]='\0';
     //fwrite(buf, ret, sizeof(char), stdout);
   //  x++;
  }

  if (close(sock) == -1)
         printf("Close socket error\n");

    printf("Bye\n");
    return 0;

 }


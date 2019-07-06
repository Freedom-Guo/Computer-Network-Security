//¿Í»§¶Ë³ÌÐò
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 
#define BUFF_SIZE 2000
#define PORT_NUMBER 4433
// need to change to 10.0.2.?
#define SERVER_IP "10.0.2.9" 

SSL* setupTLSClient(const char* hostname)
{
  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL* ssl;

  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
	struct sockaddr_in server_addr;
	
	// Get the IP address from hostname
	struct hostent* hp = gethostbyname(hostname);
	
	// Create a TCP socket
	int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	// Fill in the destination information (IP, port #, and family)
	memset (&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	//server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	server_addr.sin_port   = htons (port);
	server_addr.sin_family = AF_INET;
	
	// Connect to the destination
	connect(sockfd, (struct sockaddr*) &server_addr,
	        sizeof(server_addr));
	
	return sockfd;
}

int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

	tunfd = open("/dev/net/tun", O_RDWR);
	ioctl(tunfd, TUNSETIFF, &ifr);       

	return tunfd;
}

void tunSelected(int tunfd, SSL * ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\t");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    /*printf("packet length is %d \n",len);
	printf("packet content:");
	for(int i =0;i<len; ++i)
	{
		printf("%x ",(unsigned char)buff[len]);
	}
	*/
    SSL_write(ssl,buff,len);
    /*sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                    sizeof(peerAddr));*/
}

void socketSelected (int tunfd, SSL * ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    buff[len] = '\0';
   /* printf("packet length is %d \n",len);
	printf("packet content:");
	for(int i =0;i<len; ++i)
	{
		printf("%x ",(unsigned char)buff[len]);
	}
*/
    write(tunfd, buff, len);
}
void loginRequest(char * userName, char* passwd, SSL* ssl)
{
   SSL_write(ssl,userName,strlen(userName));
   SSL_write(ssl,passwd,strlen(userName));
}

int main(int argc, char*argv[])
{
	char * hostname = "liziqiaoSERVER";
	int port = 4433;
	//port = 55555;
	char *userName = "seed";
	char * passwd = "dees";
	if(argc < 3)
	{
		perror("input proc username passwd\n");
		return 0;
	}
	userName = argv[1];
	passwd = argv[2];
	SSL * ssl= setupTLSClient(hostname);
	int sockfd = setupTCPClient(hostname,port);
	SSL_set_fd(ssl, sockfd);
    int tunfd  = createTunDevice();
	int err = SSL_connect(ssl); CHK_SSL(err);
	//login check need to be added;	
	loginRequest(userName,passwd,ssl);
	printf("SSL connection is successful\n");
	printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
		if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl);
  }


	return 0;
}

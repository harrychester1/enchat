#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include<arpa/inet.h>	
#include <sys/types.h> 
#include <stdlib.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <unistd.h>
#define SA struct sockaddr 

int socbind(struct sockaddr_in server, struct sockaddr_in newcli){
    int len = sizeof(newcli); 
    int sockfd = socket(server.sin_family, SOCK_STREAM, 0);
    if(sockfd == -1)
        printf("socket machine broke\n"); 
    if(bind(sockfd, (SA*)&server, sizeof(server)) != 0)
        printf("bind machine broke\n");
    if(listen(sockfd, 5) != 0)
        printf("cba to listen init\n");
    int newfd = accept(sockfd, (SA*)&newcli, &len);
    return newfd;
}


void recieve(int sockfd){ 
    char buff[2048];        // read the message from client and copy it in buffer             
    bzero(buff, 2048); 
    read(sockfd, buff, 1024);
    printf("%s\n", buff);
} 


int main(){
    int socport = 8080, sockfd;
    char msg[2048] = "hello bitch";
	struct sockaddr_in server, newcli;
    bzero(&server, sizeof(server));
    server.sin_addr.s_addr = htonl(INADDR_ANY); 
    server.sin_family = AF_INET;
	server.sin_port = htons(socport);
    printf("binding to socket\n");
    sockfd = socbind(server, newcli);
    printf("waiting for incoming message\n");
    recieve(sockfd);
    close(sockfd);
}
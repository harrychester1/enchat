#include <stdio.h>
#include <sys/socket.h> 
#include<arpa/inet.h>	
#include <netdb.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h>
#define SA struct sockaddr 

int socconnect(struct sockaddr_in server){
    int sockfd = socket(server.sin_family, SOCK_STREAM, 0);
    if (sockfd == -1)
        printf("socket machine broke\n"); 
    if(connect(sockfd, (SA*)&server, sizeof(server)) != 0)
        printf("connect broke\n");
    return sockfd;
}

void sendmessage(int sockfd, char msg[2048]) 
{ 
    write(sockfd, msg, 2048);  
    //read(sockfd, msg, strlen(msg)+1); 
    printf("To Server : %s\n", msg); 
    if((strncmp(msg, "exit", 4)) == 0)
        printf("Client Exit...\n");  
} 

int main(){
    char msg[2048] = "hello im harry";
    int socport = 8080;
	struct sockaddr_in server;
    bzero(&server, sizeof(server));
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
	server.sin_port = htons(socport);
    int sockfd = socconnect(server);
    sendmessage(sockfd, msg);
    close(sockfd); 
}
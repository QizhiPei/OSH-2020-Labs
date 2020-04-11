#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(){
	char buffer[20];
        read(30 , buffer, sizeof(buffer));
	for(int i = 0 ; i < 20 ; ++i){
		printf("%c  " , buffer[i]);
	}	
	printf("\n");
        return 0;
}

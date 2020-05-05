#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

//final version
struct Pipe {
    int fd_send;
    int fd_recv;
};

void *handle_chat(void *data) {
    struct Pipe *pipe = (struct Pipe *)data;
    char buffer[1048600];
    char buffertemp1[1048600];
    int i = 0, j, k , flag = 0;
    int send_check;
    int length;
    ssize_t len;
    while ((len = recv(pipe->fd_send, buffer , 1048576, 0)) > 0) {
        length = strlen(buffertemp1);
        memcpy(buffertemp1 + length, buffer , len);
        for(i = 0; i < strlen(buffertemp1) ; ++i){
            flag = 0;
            if(buffertemp1[i] == '\n'){
                flag = 0;
                char buffertemp[1048600] = "Message:";
                //以换行为分割符进行消息分割
                for(j = 0 , k = 8; j < i ; ++j){
                    buffertemp[k++] = buffertemp1[j];
                }
                buffertemp[k] = '\n';
                //检查是否发送完全,处理可能的send阻塞
                send_check = send(pipe->fd_recv, buffertemp,  strlen(buffertemp), 0);
                //printf("Bytes: %d ", send_check);
                while (strlen(buffertemp) != send_check){
                    int i1 , i2 = 0;
                    char buffertemp3[1048600];
                    memset(buffertemp3, '\0', 1048600);
                    for(i1 = send_check ; i1 < strlen(buffertemp) ; ++i1){
                        buffertemp3[i2++] = buffertemp[i1];
                    }
                    memset(buffertemp, '\0', 1048600);
                    memcpy(buffertemp, buffertemp3, 1048600);
                    send_check = send(pipe->fd_recv , buffertemp , strlen(buffertemp) , 0);
                }
                int l1 = 0;
                int l;
                char buffertemp2[1048600];
                memset(buffertemp2, '\0', 1048600);
                for(l = i + 1 ; l < strlen(buffertemp1) ; ++l){
                    buffertemp2[l1++] = buffertemp1[l];
                    flag = 1;
                }
                memset(buffertemp1, '\0', 1048600);
                memcpy(buffertemp1, buffertemp2, 1048600);
                //i = 0;
                if (strlen(buffertemp1) == 0)   memset(buffertemp1, '\0', 1048600);
                if(flag)    i = -1;
                else{
                    /*for(int n = 0 ; n < i + 1 ; ++n){
                        buffertemp1[n] = '\0';
                        //memset(buffertemp1, '\0', 1048600);

                    }*/
                    memset(buffertemp1, '\0', 1048600);
                    i = -1;
                }
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int fd;
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    socklen_t addr_len = sizeof(addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind");
        return 1;
    }
    if (listen(fd, 2)) {
        perror("listen");
        return 1;
    }
    int fd1 = accept(fd, NULL, NULL);
    int fd2 = accept(fd, NULL, NULL);
    if (fd1 == -1 || fd2 == -1) {
        perror("accept");
        return 1;
    }
    pthread_t thread1, thread2;
    struct Pipe pipe1;
    struct Pipe pipe2;
    pipe1.fd_send = fd1;
    pipe1.fd_recv = fd2;
    pipe2.fd_send = fd2;
    pipe2.fd_recv = fd1;
    pthread_create(&thread1, NULL, handle_chat, (void *)&pipe1);
    pthread_create(&thread2, NULL, handle_chat, (void *)&pipe2);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    return 0;
}

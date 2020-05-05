#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <queue>
#include <iostream>

#define MAX_CLIENT 32
#define BUFFER_SIZE 1024 * 1024 + 20
using namespace std;
char msg_model [BUFFER_SIZE];

struct  Client{
    pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t  cv = PTHREAD_COND_INITIALIZER;
    queue<char *> send_queue;//消息队列
    int client_fd = 0;
}Clients[MAX_CLIENT];

int client_num = 0;

void *handle_recv(void *data) {
    int fd =*(int *)data;
    int fd1;
    char buffer[BUFFER_SIZE];
    char buffertemp1[BUFFER_SIZE];
    int i, j, k , flag = 0;
    int length;
    ssize_t len;
    while (1) {
        fd1 = accept(fd, NULL, NULL);
        if (fd1 == -1) {
            perror("accept");
            return NULL;
        }
        for (i = 0; i < MAX_CLIENT; ++i) {
            if (Clients[i].client_fd == 0) {
                Clients[i].client_fd = fd1;
                break;
            }
        }
        while ((len = recv(fd1, buffer, 1024 * 1024, 0)) > 0) {
            length = strlen(buffertemp1);
            memcpy(buffertemp1 + length, buffer, len);
            for (i = 0; i < strlen(buffertemp1); ++i) {
                flag = 0;
                if (buffertemp1[i] == '\n') {
                    flag = 0;
                    char buffertemp[BUFFER_SIZE] = "Message:";
                    for (j = 0, k = 8; j < i; ++j) {
                        buffertemp[k++] = buffertemp1[j];
                    }
                    buffertemp[k] = '\n';
                    for (int l = 0; l < MAX_CLIENT; ++l) {//改动
                        if (Clients[l].client_fd != 0 && Clients[l].client_fd != fd1) {
                            pthread_mutex_lock(&Clients[l].send_mutex);
                            Clients[l].send_queue.push(buffertemp);
                            pthread_cond_signal(&Clients[l].cv);
                            pthread_mutex_unlock(&Clients[l].send_mutex);
                        }
                    }
                    int l1 = 0;
                    int l;
                    char buffertemp2[BUFFER_SIZE];
                    memset(buffertemp2, '\0', BUFFER_SIZE);
                    for (l = i + 1; l < strlen(buffertemp1); ++l) {
                        buffertemp2[l1++] = buffertemp1[l];
                        //buffertemp1[l] = '\0';
                        flag = 1;
                    }
                    memset(buffertemp1, '\0', BUFFER_SIZE);
                    memcpy(buffertemp1, buffertemp2, BUFFER_SIZE);
                    if (strlen(buffertemp1) == 0) memset(buffertemp1, '\0', BUFFER_SIZE);
                    if (flag) i = -1;//若成功读取了一个以换行符结尾的消息，且还有后续消息，则重置i
                    else {//若当前buffertemp1中只有一条完整的消息
                        /*for (int n = 0; n < i + 1; ++n) {
                            buffertemp1[n] = '\0';*/
                        memset(buffertemp1, '\0', BUFFER_SIZE);
                        i = -1;
                    }
                }
            }
        }
        if (len <= 0) {
            for (int i = 0; i < MAX_CLIENT; ++i) {
                if (fd1 == Clients[i].client_fd) {
                    Clients[i].client_fd = 0;
                }
            }
        }
    }
    return NULL;
}


void *handle_send(void *data) {
    struct Client *c = (struct Client *)data;
    int send_check;
    while(1){
        pthread_mutex_lock(&c->send_mutex);
        char msg[BUFFER_SIZE];
        memset(msg, '\0', BUFFER_SIZE);
        while (c->send_queue.empty()){
            pthread_cond_wait(&c->cv, &c->send_mutex);
        }
        strcpy(msg , c->send_queue.front());
        c->send_queue.pop();
        pthread_mutex_unlock(&c->send_mutex);
        send_check = send(c->client_fd, msg,  strlen(msg), 0);
        while (strlen(msg) != send_check) {
            int i1, i2 = 0;
            char msg1[BUFFER_SIZE];
            memset(msg1, '\0', BUFFER_SIZE);
            for (i1 = send_check; i1 < strlen(msg); ++i1) {
                msg1[i2++] = msg[i1];
                //msg[i1] = '\0';
            }//将已发送的部分用未发送的部分覆盖
            memset(msg, '\0', BUFFER_SIZE);
            memcpy(msg, msg1, BUFFER_SIZE);
            send_check = send(c->client_fd, msg, strlen(msg), 0);
        }
    }
}


int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int fd;
    int i, k=0;
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
    if (listen(fd, MAX_CLIENT)) {
        perror("listen");
        return 1;
    }
    int fd1[MAX_CLIENT];
    pthread_t thread_recv[MAX_CLIENT];
    pthread_t thread_send[MAX_CLIENT];
    for (i = 0; i < MAX_CLIENT; i++) {
        pthread_create(&thread_recv[i] , NULL , handle_recv , (void *)&fd);
        pthread_create(&thread_send[i] , NULL , handle_send , (void *)&Clients[i]);
    }
    for(i = 0 ; i < MAX_CLIENT ; ++i){
        pthread_join(thread_recv[i], NULL);
        pthread_join(thread_send[i], NULL);
    }
    return 0;
}

//final version

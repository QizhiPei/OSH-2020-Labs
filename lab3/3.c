#include <stdio.h>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <vector>
#include <iostream>
#include <string>

#define MAX_CLIENTS 32
#define BUFFER_SIZE 1024 * 1024 + 20
using namespace std;
int fd_array[MAX_CLIENTS]={0};

struct MessageReader {
    vector<string> msgs;
    int feed(string buffertemp1) {
        int i, j = 0, k;
        int flag = 0;
        //int flagi;
        for (i = 0; i < buffertemp1.length(); ++i) {
            if (buffertemp1[i] == '\n') {
                //flagi = i;
                char buffertemp[BUFFER_SIZE] = "Message:";
                for (k = 8; j < i; ++j) {
                    buffertemp[k++] = buffertemp1[j];
                }
                buffertemp[k] = '\n';
                ++j;
                ++flag;
                string str(buffertemp);
                msgs.push_back(str);
            }
        }
        return flag;
    };
};

struct Client {
    int client_fd = 0;
    string send_queue;//实际上只是一个字符串而已，不是真正意义的队列

    char buffer[BUFFER_SIZE];
    char buffertemp1[BUFFER_SIZE];
    MessageReader reader;

    int recv_some_data() {
        ssize_t len;
        int length;
        int flag;
        int flag_exit = 0;
        while ((len = recv(client_fd, buffer, 1024 * 1024, 0)) > 0){
            flag_exit = 1;
            length = strlen(buffertemp1);
            memcpy(buffertemp1 + length, buffer, len);
        }
        if(flag_exit){
            string s(buffertemp1);
            flag = reader.feed(s);
            int l = strlen(buffertemp1);
            if(flag > 0 && buffertemp1[l - 1] != '\n'){
                int i,i1 = 0;
                int buffertemp2[BUFFER_SIZE];
                for (i = l - 1; buffertemp1[i] != '\n'; --i);
                for(int j = i + 1; j < l ; ++j){
                    buffertemp2[i1++] = buffertemp1[j];
                }
                //保留未发送的不完整的消息
                memset(buffertemp1, '\0', sizeof(buffertemp1));
                memcpy(buffertemp1, buffertemp2, sizeof(buffertemp2));
            } else if(flag == 0){//只传来一部分消息
            }
            else{
                //清空发送缓存
                memset(buffertemp1, '\0', sizeof(buffertemp1));
            }
            return 0;
        }
        else{
            return -1;
        }

    }
    void send_msg() {
        if(!send_queue.empty()) {
            char *msg = (char *) send_queue.data();
            ssize_t len = send(client_fd, msg, strlen(msg), 0);
            send_queue = send_queue.substr(len, send_queue.length() - len);
        }//保存可能未发送的子串，保证非阻塞io下send可以完全发送
    };
} Clients[MAX_CLIENTS];


int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int fd;
    int fd_new;
    int fd_max;
    int i;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    socklen_t addr_len = sizeof(addr);
    //将服务器的fd设为非阻塞，那么后续的accept也为非阻塞
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind");
        return 1;
    }
    printf("bind done\n");
    if (listen(fd, MAX_CLIENTS)) {
        perror("listen");
        return 1;
    }
    printf("listen done\n");


    char buffer[1024 * 1024] = "Message:";
    int temp;
    fd_set read_fd;//read_fd为需要监视的描述符集
    fd_set write_fd;//监听客户端是否可写，保证了非阻塞io下send可以完全发送
    fd_max = 1;
    printf("wait for connection\n");
    while (1) {
        //handle accept
        FD_ZERO(&read_fd);
        FD_ZERO(&write_fd);
        //read_fd = temp_fd;
        //add server
        FD_SET(fd, &read_fd);
        if (fd_max < fd) {
            fd_max = fd;
        }
        //add clients
        for (i = 0; i < MAX_CLIENTS; ++i) {
            if (Clients[i].client_fd != 0) {
                fcntl(Clients[i].client_fd, F_SETFL, fcntl(Clients[i].client_fd, F_GETFL, 0) | O_NONBLOCK); // 将客户端的套接字设置成非阻塞
                FD_SET(Clients[i].client_fd, &read_fd);
                FD_SET(Clients[i].client_fd, &write_fd);
                if (fd_max < Clients[i].client_fd) {
                    fd_max = Clients[i].client_fd;
                }
            }
        }

        temp = select(fd_max + 1, &read_fd, &write_fd, NULL, NULL);
        if (temp < 0) {
            perror("select");
            continue;
        } else if (temp == 0) {
            printf("No socket ready\n");
            continue;
        } else {
            if (FD_ISSET(fd, &read_fd)) {
                int client_fd = accept(fd, NULL, NULL);
                if (client_fd > 0) {
                    int flag = -1;
                    for (i = 0; i < MAX_CLIENTS; ++i) {
                        if (Clients[i].client_fd == 0) {
                            flag = i;
                            Clients[i].client_fd = client_fd;
                            break;
                        }//分配给空闲的客户端结构体
                    }
                    if (flag >= 0) {
                        printf("add new client %d successfully\n", flag + 1);
                    } else {
                        printf("cannot add more clients\n");
                    }
                }

            }
        }
        //handle message
        for (i = 0; i < MAX_CLIENTS; ++i) {
            if (Clients[i].client_fd != 0) {
                if (FD_ISSET(Clients[i].client_fd, &read_fd)) {
                    int flag_exit;
                    flag_exit = Clients[i].recv_some_data();
                    for (auto &&msg : Clients[i].reader.msgs) {
                        for (int j = 0; j < MAX_CLIENTS; ++j) {
                            if (j != i && Clients[j].client_fd != 0) {
                                Clients[j].send_queue += msg;
                            }
                        }
                    }
                    Clients[i].reader.msgs.clear();
                    if(flag_exit == -1){
                        printf("client %d exit\n", i + 1);
                        FD_CLR(Clients[i].client_fd, &read_fd);
                        Clients[i].client_fd = 0;
                        Clients[i].reader.msgs.clear();
                        memset(Clients[i].buffertemp1, '\0' , sizeof(Clients[i].buffertemp1));
                        continue;
                    }
                }

            }
        }
        for (i = 0; i < MAX_CLIENTS; ++i) {
            if (FD_ISSET(Clients[i].client_fd, &write_fd) && Clients[i].client_fd != 0) {
                Clients[i].send_msg();
            }
        }
    }
    return 0;
}
//final version

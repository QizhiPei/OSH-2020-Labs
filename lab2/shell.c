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


void sigint(int signalNum){
    int status ;
    int result = waitpid(0 , &status , WNOHANG);
    if (result == -1){
        write(2 , "\n# " , 3);
        return;
    }else if (result  == 0){
        //write(2 , "\n" , 1);
        return;
    }
}

int main() {
    signal(SIGINT , sigint);
    signal(SIGPIPE , SIG_IGN);
    int in = dup(0);
    int out = dup(1);
    char buffer[256];

    while (1) {
        /* 输入的命令行 */

        char cmd[256];
        /* 命令行拆解成的各部分，以空指针结尾 */
        char *args[128];
        int pfds[128][2];
        int i,j;

        /* 提示符 */
        printf("# ");
        fflush(stdin);
        fgets(cmd, 256 , stdin);


        for (i = 0; cmd[i] != '\n'; i++);
        cmd[i] = '\0';
        /* 拆解命令行 */
        args[0] = cmd;
        for (i = 0; *args[i]; i++)
            for (args[i + 1] = args[i] + 1; *args[i + 1]; args[i + 1]++)
                if (*args[i + 1] == ' ') {
                    *args[i + 1] = '\0';
                    args[i + 1]++;
                    break;
                }
        args[i++] = "|";//当前i即为分出来的部分的个数
        args[i] = NULL;
        if (*args[0] == '|')
            continue;
        int count = 0;
        int length[128] = {0};
        length[0] = -1;
        int flag[128] = {0};
        int temp = -1;
        int k = 1,l;
        length[0] = 0;
        for(j = 0 ; j < i ; ++j ){
            if(*args[j] == '|'){
                ++count;
                flag[j] = 1;
                length[k++] = j - temp  + length[k-1];
                temp = j;
            }
        }
        //不带管道指令的处理
        if(count == 1){
            args[--i] = NULL;
            bool flag = false;
            bool flag1 = false;
            bool flag2 = false;
            bool flagsocout = false;
            bool flagsocin = false;
            bool flaga = false;
            bool flagb = false;
            bool flagc = false;
            bool flagd = false;
            bool flage = false;
            int fd,sock;
            int filenum;
            int filenum1,filenum2,filenum3;
            int tempnum;
            int tempnum1,tempnum2,tempnum3;
            struct sockaddr_in addr;
            for(int k = 0 ; k < length[1] - 1 ; ++k){
                if(strcmp(args[k], ">") == 0){
                    if(strncmp(args[k+1] , "/dev/tcp/" , 9) == 0){
                        sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
                        flagsocout = true;
                        bzero(&addr , sizeof(addr));
                        addr.sin_family = AF_INET;
                        char Port[10];
                        char IP[20];
                        int n = 0;
                        bool Portflag = false;
                        for(int h = 9 ; h < strlen(args[k+1]) ; ++h){
                            if(!Portflag && args[k+1][h] != '/'){
                                IP[n++] = args[k+1][h];
                            }else if(args[k+1][h] == '/'){
                                Portflag = true;
                                IP[n] = NULL;
                                n = 0;
                            } else{
                                Port[n++] = args[k+1][h];
                            }
                        }
                        Port[n] = NULL;
                        unsigned int PORT = (unsigned int)atoi(Port);
                        addr.sin_port = htons(PORT);
                        addr.sin_addr.s_addr = inet_addr(IP);
                        if((connect(sock , (const struct sockaddr*)&addr , sizeof(addr)))<0){
                            printf("Error\n");
                            return 255;
                        };
                        args[k] = NULL;
                        dup2(sock , 1);
                    }
                    else{
                        flag = true;
                        fd = open(args[k+1] , O_WRONLY | O_CREAT | O_TRUNC, 0666);
                        args[k] = NULL;
                        dup2(fd , 1);
                    }
                    break;
                }
            }
            if(!flag && !flagsocout) {
                for (int k = 0; k < length[1] - 1; ++k) {
                    if (strcmp(args[k], ">>") == 0) {
                        flag1 = true;
                        fd = open(args[k + 1], O_WRONLY | O_CREAT | O_APPEND , 0666);
                        args[k] = NULL;
                        dup2(fd, 1);
                        break;
                    }
                }
            }
            if(!flag && !flag1 && !flagsocout){
                for (int k = 0; k < length[1] - 1; ++k) {
                    if (strcmp(args[k], "<") == 0) {
                        if(strncmp(args[k+1] , "/dev/tcp/" , 9) == 0){
                            sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
                            flagsocin = true;
                            bzero(&addr , sizeof(addr));
                            addr.sin_family = AF_INET;
                            char Port[10];
                            char IP[20];
                            int n = 0;
                            bool Portflag = false;
                            for(int h = 9 ; h < strlen(args[k+1]) ; ++h){
                                if(!Portflag && args[k+1][h] != '/'){
                                    IP[n++] = args[k+1][h];
                                }else if(args[k+1][h] == '/'){
                                    Portflag = true;
                                    IP[n] = NULL;
                                    n = 0;
                                } else{
                                    Port[n++] = args[k+1][h];
                                }
                            }
                            Port[n] = NULL;
                            unsigned int PORT = (unsigned int)atoi(Port);
                            addr.sin_port = htons(PORT);
                            addr.sin_addr.s_addr = inet_addr(IP);
                            if((connect(sock , (const struct sockaddr*)&addr , sizeof(addr)))<0){
                                printf("Error\n");
                                return 255;
                            };
                            args[k] = NULL;
                            dup2(sock , 0);
                        }else{
                            flag2 = true;
                            fd = open(args[k + 1], O_RDONLY , 0666);
                            args[k] = NULL;
                            dup2(fd, 0);
                        }
                        break;
                    }
                }
            }
            if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin){
                for (int k = 0; k < length[1] - 1; ++k) {
                    if (*(args[k] + strlen(args[k]) - 1 ) == '>') {
                        flaga = true;
                        char s[64];
                        int len = strlen(args[k]) - 1;
                        strncpy(s , args[k] , len);
                        s[k+1] = NULL;
                        fd = open(args[k + 1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
                        args[k] = NULL;
                        filenum = atoi(s);
                        tempnum = dup(filenum);
                        dup2(fd, filenum);
                        break;
                    }
                }
            }
            if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga){
                bool flagcc = false;
                for (int k = 0; k < length[1] - 1; ++k) {
                    int l;
                    for(l = 0 ; l < strlen(args[k]) ; ++l){
                        if (*(args[k] + l) == '>')
                            if(*(args[k] + l + 1) == '&'){
                                flagcc = true;
                                break;
                            }
                    }
                    if(flagcc){
                        flagc = true;
                        char s1[64] , s2[64] , s3[64];
                        int len1 = l;
                        int len2 = strlen(args[k]) - l -2;
                        strncpy(s1 , args[k] , len1);
                        s1[len1] = NULL;
                        int s2num = 0;
                        for(int n = l + 2 ; n < strlen(args[k]) ; ++n){
                            s2[s2num++] = *(args[k] + n);
                        }
                        s2[s2num] = NULL;
                        int len3 = strlen(args[k+1]);
                        strncpy(s3 , args[k+1] , len3 - 1);
                        s3[len3 - 1] = NULL;
                        fd = open(args[k + 2], O_RDONLY , 0666);
                        args[k] = NULL;
                        args[k+1] = NULL;
                        args[k+2] = NULL;
                        filenum1 = atoi(s1);
                        filenum2 = atoi(s2);
                        filenum3 = atoi(s3);
                        tempnum1 = dup(filenum1);
                        tempnum2 = dup(filenum2);
                        tempnum3 = dup(filenum3);
                        dup2(fd, filenum3);
                        dup2(filenum2 , filenum1);
                        break;
                    } else {
                        continue;
                    }
                }
            }
            if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga && !flagc){
                for (int k = 0; k < length[1] - 1; ++k) {
                    char temp1[1024];
                    if (strcmp(args[k], "<<") == 0) {
                        if(strcmp(args[k+1] , "EOF") == 0){
                            flagd = true;
                            args[k] = NULL;
                            args[k+1] = NULL;
                            char cmdtemp[256];
                            int numtemp1 = 0;
                            while(1){
                                //printf("#");
                                fflush(stdin);
                                fgets(cmdtemp , 256 , stdin);
                                if(strncmp(cmdtemp , "EOF" , 3) == 0){
                                    break;
                                }else {
                                    for(int n = 0 ; n < strlen(cmdtemp) ; ++n){
                                        temp1[numtemp1++] = cmdtemp[n];
                                    }
                                    memset(cmdtemp , 0 , 256);
                                }
                            }
                        }
                        int fd1 = open("temp.txt" , O_WRONLY | O_CREAT , 0666);
                        write(fd1 , temp1 , strlen(temp1));
                        close(fd1);
                        int fd2 = open("temp.txt" , O_RDONLY , 0666);
                        dup2(fd2 , 0);
                        break;
                    }
                }
            }

            if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga && !flagc && !flagd){
                for (int k = 0; k < length[1] - 1; ++k) {
                    if (strcmp(args[k], "<<<") == 0) {
                            flage = true;
                            char cmdtemp[256];
                            strcpy(cmdtemp , args[k+1]);
                            int lentemp = strlen(cmdtemp);
                            cmdtemp[lentemp] = '\n';
                            args[k] = NULL;
                            args[k+1] = NULL;
                            int fd1 = open("temp.txt" , O_WRONLY | O_CREAT , 0666);
                            write(fd1 , cmdtemp , strlen(cmdtemp));
                            close(fd1);
                            int fd2 = open("temp.txt" , O_RDONLY , 0666);
                            dup2(fd2 , 0);
                            break;
                    }
                }
            }


            if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga && !flagc && !flagd && !flage){
                for (int k = 0; k < length[1] - 1; ++k) {
                    if (*(args[k] + strlen(args[k]) - 1 ) == '<') {
                        flagb = true;
                        char s[64];
                        int len = strlen(args[k]) - 1;
                        strncpy(s , args[k] , len);
                        s[k+1] = NULL;
                        fd = open(args[k + 1], O_RDONLY , 0666);
                        args[k] = NULL;
                        filenum = atoi(s);
                        tempnum = dup(filenum);
                        dup2(fd, filenum);
                        break;
                    }
                }
            }
            if (strcmp(args[0], "cd") == 0) {
                if (args[1])
                    chdir(args[1]);
                continue;
            }
            if (strcmp(args[0], "pwd") == 0) {
                char wd[4096];
                puts(getcwd(wd, 4096));
                if(flagsocout){
                    dup2(out , 1);
                }
                if(flaga || flagb){
                    dup2(tempnum , filenum);
                }
                if(flagc){
                    dup2(tempnum1 , filenum1);
                    dup2(tempnum2 , filenum2);
                    dup2(tempnum3 , filenum3);
                }
                if(flag || flag1){
                    dup2(out , 1);
                }
                else if(flag2){
                    dup2(in , 0);
                }
                continue;
            }
            if (strcmp(args[0], "export") == 0) {
                for (i = 1; args[i] != NULL; i++) {
                    /*处理每个变量*/
                    char *name = args[i];
                    char *value = args[i] + 1;
                    while (*value != '\0' && *value != '=')
                        value++;
                    *value = '\0';
                    value++;
                    setenv(name, value, 1);
                    if(flagsocout){
                        dup2(out , 1);
                    }

                    if(flag || flag1){
                        dup2(out , 1);
                    }
                    if(flagc){
                        dup2(tempnum1 , filenum1);
                        dup2(tempnum2 , filenum2);
                        dup2(tempnum3 , filenum3);
                    }

                    if(flaga || flagb){
                        dup2(tempnum , filenum);
                    }
                }
                continue;
            }
            if (strcmp(args[0], "exit") == 0)
                return 0;


            /* 外部命令 */
            pid_t pid3 = fork();
            if (pid3 == 0) {
                /* 子进程 */
                execvp(args[0], args);
                /* execvp失败 */
                return 255;
            }
            /* 父进程 */
            wait(NULL);
            if(flagsocout){
                dup2(out , 1);
            }
            if(flagsocin){
                dup2(in , 0);
            }
            if(flaga || flagb){
                dup2(tempnum , filenum);
            }
            if(flagc){
                dup2(tempnum1 , filenum1);
                dup2(tempnum2 , filenum2);
                dup2(tempnum3 , filenum3);
            }
            if(flagd || flage){
                remove("temp.txt");//删除临时创建的缓存文件，后续会删除
                dup2(in , 0);
            }
            if(flag || flag1){
                dup2(out , 1);
            }
            else if(flag2){
                dup2(in , 0);
            }
            continue;

        }


        //带管道指令的处理

        int sock;

        for(i = 0 ; i < count-1 ; ++i){
            pipe(pfds[i]);
        }
        for (i = 0 ; i < count; ++i){
            pid_t pid = fork();
            if(pid < 0){
                printf("Error\n");
                exit(-1);
            }
            else if(pid == 0){//child process
                char *args1[128];
                int a = 0;
                for(l = length[i] ; strcmp (args[l] , "|") != 0 ; ++l){//*args[l] != '|'
                    args1[a] = args[length[i] + a];
                    a++;
                }
                args1[a] = NULL;
                bool flag = false;
                bool flag1 = false;
                bool flag2 = false;
                bool flaga = false;
                bool flagb = false;
                bool flagc = false;
                bool flage = false;
                bool flagsocout = false;
                bool flagsocin = false;
                int filenum;
                int filenum1,filenum2,filenum3;
                int tempnum;
                int tempnum1,tempnum2,tempnum3;
                struct sockaddr_in addr;
                int fd;
                for(int k = 0 ; k < length[i+1]- length[i] - 1 ; ++k){
                    if(strcmp(args1[k], ">") == 0){
                        if(strncmp(args1[k+1] , "/dev/tcp/" , 9) == 0){
                            sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
                            flagsocout = true;
                            bzero(&addr , sizeof(addr));
                            addr.sin_family = AF_INET;
                            char Port[10];
                            char IP[20];
                            int n = 0;
                            bool Portflag = false;
                            for(int h = 9 ; h < strlen(args1[k+1]) ; ++h){
                                if(!Portflag && args1[k+1][h] != '/'){
                                    IP[n++] = args1[k+1][h];
                                }else if(args1[k+1][h] == '/'){
                                    Portflag = true;
                                    IP[n] = NULL;
                                    n = 0;
                                } else{
                                    Port[n++] = args1[k+1][h];
                                }
                            }
                            Port[n] = NULL;
                            unsigned int PORT = (unsigned int)atoi(Port);
                            addr.sin_port = htons(PORT);
                            addr.sin_addr.s_addr = inet_addr(IP);
                            if((connect(sock , (const struct sockaddr*)&addr , sizeof(addr)))<0){
                                printf("Error\n");
                                return 255;
                            };
                            args1[k] = NULL;
                            dup2(sock , 1);
                        }
                        else{
                            flag = true;
                            fd = open(args1[k+1] , O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            args1[k] = NULL;
                            dup2(fd , 1);
                        }
                        break;
                    }
                }

                if(!flag && !flagsocout) {
                    for (int k = 0; k < length[i+1] - length[i] - 1; ++k) {
                        if (strcmp(args1[k], ">>") == 0) {
                            flag1 = true;
                            fd = open(args1[k + 1], O_WRONLY | O_CREAT | O_APPEND , 0666);
                            args1[k] = NULL;
                            dup2(fd, 1);
                            break;
                        }
                    }
                }
                if(!flag && !flagsocout && !flag1){
                    for (int k = 0; k < length[i+1] - length[i] - 1; ++k) {
                        if (strcmp(args1[k], "<") == 0) {
                            if(strncmp(args1[k+1] , "/dev/tcp/" , 9) == 0){
                                sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
                                flagsocin = true;
                                bzero(&addr , sizeof(addr));
                                addr.sin_family = AF_INET;
                                char Port[10];
                                char IP[20];
                                int n = 0;
                                bool Portflag = false;
                                for(int h = 9 ; h < strlen(args1[k+1]) ; ++h){
                                    if(!Portflag && args1[k+1][h] != '/'){
                                        IP[n++] = args1[k+1][h];
                                    }else if(args1[k+1][h] == '/'){
                                        Portflag = true;
                                        IP[n] = NULL;
                                        n = 0;
                                    } else{
                                        Port[n++] = args1[k+1][h];
                                    }
                                }
                                Port[n] = NULL;
                                unsigned int PORT = (unsigned int)atoi(Port);
                                addr.sin_port = htons(PORT);
                                addr.sin_addr.s_addr = inet_addr(IP);
                                if((connect(sock , (const struct sockaddr*)&addr , sizeof(addr)))<0){
                                    printf("Error\n");
                                    return 255;
                                };
                                args1[k] = NULL;
                                dup2(sock , 0);
                            }else{
                                flag2 = true;
                                fd = open(args1[k + 1], O_RDONLY , 0666);
                                args1[k] = args[k+1];
                                args1[k+1] = NULL;
                                dup2(fd, 0);
                            }
                            break;
                        }
                    }
                }
                if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin){
                    for (int k = 0; k < length[i+1] - length[i] - 1; ++k) {
                        if (*(args1[k] + strlen(args1[k]) - 1 ) == '>') {
                            flaga = true;
                            char s[64];
                            int len = strlen(args1[k]) - 1;
                            strncpy(s , args1[k] , len);
                            s[k+1] = NULL;
                            fd = open(args1[k + 1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            args1[k] = NULL;
                            filenum = atoi(s);
                            tempnum = dup(filenum);
                            dup2(fd, filenum);
                            break;
                        }
                    }
                }

                if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga){
                    bool flagcc = false;
                    for (int k = 0; k < length[i+1] - length[i] - 1; ++k) {
                        int l;
                        for(l = 0 ; l < strlen(args1[k]) ; ++l){
                            if (*(args1[k] + l) == '>')
                                if(*(args1[k] + l + 1) == '&'){
                                    flagcc = true;
                                    break;
                                }
                        }
                        if(flagcc){
                            flagc = true;
                            char s1[64] , s2[64] , s3[64];
                            int len1 = l;
                            int len2 = strlen(args1[k]) - l -2;
                            strncpy(s1 , args1[k] , len1);
                            s1[len1] = NULL;
                            int s2num = 0;
                            for(int n = l + 2 ; n < strlen(args1[k]) ; ++n){
                                s2[s2num++] = *(args1[k] + n);
                            }
                            s2[s2num] = NULL;
                            int len3 = strlen(args1[k+1]);
                            strncpy(s3 , args1[k+1] , len3 - 1);
                            s3[len3 - 1] = NULL;
                            fd = open(args1[k + 2], O_RDONLY , 0666);
                            args1[k] = NULL;
                            args1[k+1] = NULL;
                            args1[k+2] = NULL;
                            filenum1 = atoi(s1);
                            filenum2 = atoi(s2);
                            filenum3 = atoi(s3);
                            tempnum1 = dup(filenum1);
                            tempnum2 = dup(filenum2);
                            tempnum3 = dup(filenum3);
                            dup2(fd, filenum3);
                            dup2(filenum2 , filenum1);
                            break;
                        } else {
                            continue;
                        }
                    }
                }

                if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga && !flagc){
                    for (int k = 0; k < length[i+1] - length[i] - 1; ++k) {
                        if (strcmp(args1[k], "<<<") == 0) {
                            flage = true;
                            char cmdtemp[256];
                            strcpy(cmdtemp , args1[k+1]);
                            int lentemp = strlen(cmdtemp);
                            cmdtemp[lentemp] = '\n';
                            args1[k] = NULL;
                            args1[k+1] = NULL;
                            int fd1 = open("temp.txt" , O_WRONLY | O_CREAT , 0666);
                            write(fd1 , cmdtemp , strlen(cmdtemp));
                            close(fd1);
                            int fd2 = open("temp.txt" , O_RDONLY , 0666);
                            dup2(fd2 , 0);
                            break;
                        }
                    }
                }

                if(!flag && !flag1 && !flagsocout && !flag2 && !flagsocin && !flaga && !flagc && !flage){
                    for (int k = 0; k < length[i+1] - length[i] - 1; ++k) {
                        if (*(args1[k] + strlen(args1[k]) - 1 ) == '<') {
                            flagb = true;
                            char s[64];
                            int len = strlen(args1[k]) - 1;
                            strncpy(s , args1[k] , len);
                            s[k+1] = NULL;
                            fd = open(args1[k + 1], O_RDONLY , 0666);
                            args1[k] = NULL;
                            filenum = atoi(s);
                            tempnum = dup(filenum);
                            dup2(fd, filenum);
                            break;
                        }
                    }
                }
                if(i + 1 < count){
                    close(pfds[i][0]);
                    dup2(pfds[i][1],1);
                    close(pfds[i][1]);
                }

                if (strcmp(args1[0], "cd") == 0) {
                    if (args1[1])
                        chdir(args1[1]);
                    exit(255);
                }
                if (strcmp(args1[0], "pwd") == 0) {
                    char wd[4096];
                    puts(getcwd(wd, 4096));
                    exit(255);
                }
                if (strcmp(args1[0], "export") == 0) {
                    for (int num = 1; args1[num] != NULL; num++) {
                        //处理每个变量
                        char *name = args1[num];
                        char *value = args1[num] + 1;
                        while (*value != '\0' && *value != '=')
                            value++;
                        *value = '\0';
                        value++;
                        setenv(name, value, 1);
                    }
                    exit(255);
                }
                if (strcmp(args1[0], "exit") == 0)
                    return 0;

                pid_t pid2 = fork();
                if(pid2 == 0){
                    execvp(args1[0], args1);
                    return 255;
                }

                wait(NULL);
                if(flage)
                    remove("temp.txt");

                exit(255);
            }
            else {
                wait(NULL);
                if(i + 1 < count){
                    close(pfds[i][1]);//
                    dup2(pfds[i][0], 0);//
                    close(pfds[i][0]);
                }

                if(i + 1 == count){
                    dup2(in , 0);//恢复重定向
                    dup2(out , 1);
                    }
            }

        }

    }
}
//最终版本
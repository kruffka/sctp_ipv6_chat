#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/sctp.h>
#include <string.h>

char buffer[1024];

#define STDIN 0
#define CHAT_PORT 62324

int main(int argc, char *argv[]) {

        char my_nickname[20];

        int sockfd;
        int nread, nsent;
        int flags, len;
        struct sockaddr_in6 serv_addr;
        struct sctp_sndrcvinfo sinfo;
        fd_set readfds;

        /* create endpoint using  SCTP */
        sockfd = socket(AF_INET6, SOCK_SEQPACKET,
                        IPPROTO_SCTP);
        if (sockfd < 0) {
                perror("socket creation failed");
                exit(2); }
        /* connect to server */
        serv_addr.sin6_family = AF_INET6;
        serv_addr.sin6_port = htons(CHAT_PORT);
        inet_pton(AF_INET6, "::1", &serv_addr.sin6_addr);

        if (connect(sockfd,
                    (struct sockaddr *) &serv_addr,
                    sizeof(serv_addr)) < 0) {
                perror("connect to server failed");
                exit(3);
        }
        struct sctp_event_subscribe events;

        bzero(&events, sizeof(events));
        events.sctp_data_io_event = 1;
        int ret = setsockopt(sockfd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events));
        if (ret < 0) {
                perror("setsockopt");
                exit(2); }

        printf("Connected\n");

        for (;;) {    

                printf("<type here>:");
                fflush(stdout);

                FD_CLR(sockfd, &readfds);
                FD_SET(sockfd, &readfds);
                FD_SET(STDIN, &readfds);
                select(sockfd+1, &readfds, NULL, NULL, NULL);

                if (FD_ISSET(STDIN, &readfds)) {
                        // printf("reading from stdin\n");
                        nread = read(0, buffer, sizeof(buffer));
                        if (nread <= 0 )
                                break;

                        ret = sctp_sendmsg(sockfd, buffer, nread, (struct sockaddr *) &serv_addr, len, 0, 0, 0, 0, 0);
                        if (ret < 0) {
                                printf("sctp_sendmsg\n");
                                exit(1);

                        }
                
                        // \33[2K Стирает линию на которой сейчас находится курсор
                        // \033[A Двигаает курсор на одну линию вверх (к той же колонке где и был)
                        // \r - Помещает курсор вначало
                        printf("\033[A\033[2K\r");
                        fflush(stdout);


                } else if (FD_ISSET(sockfd, &readfds)) {
                        // printf("Reading from socket\n");
                        len = sizeof(serv_addr);
                        nread = sctp_recvmsg(sockfd, buffer, sizeof(buffer),
                                     (struct sockaddr *) &serv_addr,
                                     &len,
                                     &sinfo, &flags);

                        // printf("%hu %hu %hu %u %u %u %u %u %d\n", sinfo.sinfo_stream,
                        //                                 sinfo.sinfo_ssn,
                        //                                 sinfo.sinfo_flags,
                        //                                 sinfo.sinfo_ppid,
                        //                                 sinfo.sinfo_context,
                        //                                 sinfo.sinfo_timetolive,
                        //                                 sinfo.sinfo_tsn,
                        //                                 sinfo.sinfo_cumtsn,
                        //                                 sinfo.sinfo_assoc_id);
                        
                        if (buffer[0] == '/') {

                                char *cmd = strtok(buffer, " \n");
                                if (!strcmp(cmd, "/fsend")) {
                                        
                                        cmd = strtok(NULL, " \n");
                                        if (cmd) {
                                                FILE *file = fopen(cmd, "rb");
                                                if (file == NULL) {
                                                        printf("\033[2K\r");
                                                        printf("[Client] No such file or directory\n");
                                                        fflush(stdout);
                                                        sprintf(buffer, "/fclose");

                                                        // stream 1 для отправки файлов на сервер
                                                        ret = sctp_sendmsg(sockfd, buffer, nread, (struct sockaddr *) &serv_addr, len, 0, 0, 1, 0, 0);
                                                        if (ret < 0) {
                                                                printf("sctp_sendmsg()\n");
                                                                exit(1);

                                                        }
                                                        continue;
                                                }
                                                do {
                                                        nread = fread(buffer, 1, sizeof(buffer), file);
                                                        // printf("Client] Sent %d bytes\n", nread);

                                                        if (nread <= 0) {
                                                                break;
                                                        }


                                                        ret = sctp_sendmsg(sockfd, buffer, nread, (struct sockaddr *) &serv_addr, len, 0, 0, 1, 0, 0);
                                                        if (ret < 0) {
                                                                printf("sctp_sendmsg()\n");
                                                                exit(1);

                                                        }
                                                } while (nread == sizeof(buffer));        

                                                fclose(file);

                                        } else {
                                                // Невозможная ситуация?
                                                printf("[Client] /f command is empty from server, not sending anything!\n");
                                                // exit(1);
                                        }
                                        continue;

                                }

                                if (!strcmp(cmd, "/frecv")) {
                                        // printf("\n[Client] Trying to download file from server\n");

                                        char path[48];
                                        cmd = strtok(NULL, " \n");
                                        if (cmd) {
                                                sprintf(path, "Downloads/%s", cmd);

                                                FILE *file = fopen(path, "wb");
                                                if (file == NULL) {
                                                        printf("[Client] No such file or directory\n");
                                                        sprintf(buffer, "/fclose");

                                                        // stream 1 для отправки файлов на сервер
                                                        ret = sctp_sendmsg(sockfd, buffer, nread, (struct sockaddr *) &serv_addr, len, 0, 0, 2, 0, 0);
                                                        if (ret < 0) {
                                                                printf("sctp_sendmsg()\n");
                                                                exit(1);

                                                        }
                                                        continue;
                                                }

                                                // принимаем файл и записываем его по пути Downloads/file_name
                                                do {

                                                        nread = sctp_recvmsg(sockfd, buffer, sizeof(buffer),
                                                                (struct sockaddr *) &serv_addr,
                                                                &len,
                                                                NULL, NULL);
                                                        
                                                        // printf("[Client] recv %d bytes\n", nread);


                                                        fwrite(buffer, 1, nread, file);

                        
                                                } while (nread == sizeof(buffer));        

                                                fclose(file);
                                                printf("\033[2K\r");
                                                printf("[Client] File downloaded to %s\n", path);
                                                fflush(stdout);
                                                memset(buffer, 0, sizeof(buffer));


                                        } else {
                                                // Невозможная ситуация?
                                                printf("[Client] /f command is empty from server, not sending anything!\n");
                                                // exit(1);
                                        }

                                        continue;

                                }
                        }


                        printf("\033[2K\r");
                        fflush(stdout);
                        write(1, buffer, nread);
                }


        }
        close(sockfd);
        exit(0);
}
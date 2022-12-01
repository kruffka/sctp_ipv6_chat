#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/sctp.h>

#include <stdint.h>
#include <string.h>
#include <time.h>

#define HELP_MSG "[Server] HELP MESSAGE\n"                                          \
                        "[Server] /help - to print out this help message\n"         \
                        "[Server] /m *username* -  private message to user\n"       \
                        "[Server] /list - list of connected users\n"                \
                        "[Server] /f *file_name* - to upload file to server\n"      \
                        "[Server] /d *file_name* - to download file from server\n"
                        // "[Server] /exit - close connection and exit\n"
                        // "[Server] /login *your_name* - to login\n"                  \
                        // "[Server] /passwd *password* - to send password\n"          \

// TODO макрос или функцию для логов и сообщений..
// TODO освобождать память при отключении клиента..
// TODO отправка файлов клиентам отдельным потоком?


#define CHAT_PORT 62324

typedef struct credentials {
        char login[20];
        char passwd[20];
} credentials_t;

typedef struct client_list client_list_t;

typedef struct client_list {

        char *name;
        char *pass;
        char *fname_upload;
        char *fname_dload;
        FILE *fileP[2]; // 0 - Upload, 1 - DL
        int registered;
        int logged;
        sctp_assoc_t assoc_id; // int32_t
        client_list_t *next_client;
        struct sockaddr_in6 client_addr6;

} client_list_t;


static void die(const char *s) {
        perror(s);
        exit(1);
}

static void exit_fun(const char *s) {
        perror(s);

        // todo remove_clients
        //
        fflush(stderr);
        fflush(stdout);
        exit(1);
}

client_list_t *new_client(sctp_assoc_t assoc_id) {

       client_list_t *client_list = (client_list_t *)malloc(sizeof(client_list_t));
       client_list->next_client = NULL;
       client_list->assoc_id = assoc_id;
       client_list->registered = 0;
       client_list->logged = 0;
       client_list->name = NULL;
       client_list->pass = NULL;
       client_list->fname_dload = NULL;
       client_list->fname_upload = NULL;
       client_list->fileP[0] = NULL;
       client_list->fileP[1] = NULL;
       memset(&client_list->client_addr6, 0, sizeof(client_list->client_addr6));
       return client_list;
}

void remove_client(client_list_t *client_list) {


        // free name
        // free(client_list);
}


int is_new_client(client_list_t **client_list, sctp_assoc_t assoc_id, client_list_t **current_client) {

        client_list_t *clientP = *client_list;

        while(clientP) {

                // printf("(*client_list)->assoc_id == assoc_id %d %d\n", clientP->assoc_id, assoc_id);

                // если в списке клиентов уже есть такой assoc_id - клиент уже в списке подключенных
                if (clientP->assoc_id == assoc_id) {
                        // printf("old\n");
                        *current_client = clientP;
                        return 0;
                }
                // переход по списку клиентов
                clientP = clientP->next_client;
        };

        // в случае если не нашли создадим нового
        if (*client_list) {
                clientP = *client_list;

                while (clientP->next_client) { 
                        clientP = clientP->next_client;
                }
                clientP->next_client = new_client(assoc_id);
                *current_client = clientP->next_client;

        } else {
                // Если первое подключение
                *client_list = new_client(assoc_id);
                *current_client = *client_list;
        }

        // printf("new\n");
        return 1;
}

int search_user_db(client_list_t *current_client) {


        credentials_t client;
        FILE *file = fopen("passwd", "r");
        if (file == NULL) {
                exit_fun("Error opening file passwd.txt!");
        }

        int registered = 0;
        // Ищем в файле информацию
        while (fread(&client, sizeof(client), 1, file)) {

                printf("login %s passwd %s current_client name %s\n", client.login, client.passwd, current_client->name);
                if (!strcmp(client.login, current_client->name)) {
                        registered = 1;
                        printf("[%d] <%s> Client exists in database\n", current_client->assoc_id, current_client->name);
                        current_client->pass = strdup(client.passwd);
                        break;
                }
        }


        fclose(file);

        return registered;
}

int find_user(client_list_t *client_list, char *name, struct sockaddr_in6 *client_addr) {

        int found = 0;
        client_list_t *clientP = client_list;

        while (clientP) { 
                if (!strcmp(clientP->name, name)) {
                        found = 1;
                        client_addr->sin6_family = clientP->client_addr6.sin6_family;
                        // client_addr->sin_addr.s_addr = clientP->client_addr.sin_addr.s_addr;
                        client_addr->sin6_port = clientP->client_addr6.sin6_port;
                        memcpy(&client_addr->sin6_addr, &clientP->client_addr6.sin6_addr, sizeof(clientP->client_addr6.sin6_addr));

                        break;
                }
                
                clientP = clientP->next_client;
        }

        return found;
}

int register_new_client(client_list_t *current_client) {

        credentials_t client;
        sprintf(client.login, "%s", current_client->name);
        sprintf(client.passwd, "%s", current_client->pass);


        FILE *file = fopen("passwd", "a+");
        if (file == NULL) {
                exit_fun("Error opening file passwd.txt!");
        }

        // Ищем в файле информацию
        fwrite(&client, sizeof(client), 1, file);

        printf("[%d] <%s> New client is added to database\n", current_client->assoc_id, current_client->name);

        fclose(file);
}


char buffer[1548];
char sendbuffer[1548];

int main(int argc, char **argv) {

        int sockfd, ret, flags, len, nread;
        int sock_server, listenfd;

        struct sockaddr_in6 serv_addr, client_addr6;
        struct sctp_event_subscribe events;
        struct sctp_sndrcvinfo sinfo;

        len = sizeof(client_addr6);

        // Создаем endpoint
        // one-to-many socket
        sockfd = socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP);
        if (sockfd < 0)
                die("socket");

        // Привязываем адрес
        serv_addr.sin6_family = AF_INET6;
        serv_addr.sin6_port = htons(CHAT_PORT);
        inet_pton(AF_INET6, "0::1", &serv_addr.sin6_addr); // 0:0:0:0:0:0:0:1

        ret = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        if (ret < 0)
                die("bind");

        // Опции сокета
        bzero(&events, sizeof(events));
        events.sctp_data_io_event = 1;
        ret = setsockopt(sockfd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events));
        if (ret < 0)
                die("setsockopt");


        
        if (getsockname(sockfd, (struct sockaddr *)&serv_addr, &len)) {
                die("getsockname");
        }

        char s[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, &(serv_addr.sin6_addr), s, INET6_ADDRSTRLEN) == NULL) {
                die("inet_ntop");
        }
	printf("[Server] IPv6:port -> %s:%d\n", s, ntohs(serv_addr.sin6_port));



        // struct sctp_initmsg initmsg;
        // memset(&initmsg, 0, sizeof(initmsg));
        // initmsg.sinit_num_ostreams = 1,
        // initmsg.sinit_max_instreams = 1,
        // initmsg.sinit_max_attempts = 5,

        // ret = setsockopt(sockfd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg));
        // if (ret < 0)
        //         die("setsockopt");


        // Очередь
        listen(sockfd, 5);
        printf("Listening\n");


        client_list_t *client_list = NULL;
        client_list_t *current_client = NULL;

        struct tm tm;               
        time_t t;

        for (;;) {


                len = sizeof(client_addr6);
                nread = sctp_recvmsg(sockfd, buffer, sizeof(buffer),
                                   (struct sockaddr *) &client_addr6,
                                   &len,
                                   &sinfo, 0);
                

                if (nread <= 0) {
                        close(sockfd);
                        exit(1);
                }
                

                // printf("%hu %hu %hu %u %u %u %u %u %d\n", sinfo.sinfo_stream,
                //                                 sinfo.sinfo_ssn,
                //                                 sinfo.sinfo_flags,
                //                                 sinfo.sinfo_ppid,
                //                                 sinfo.sinfo_context,
                //                                 sinfo.sinfo_timetolive,
                //                                 sinfo.sinfo_tsn,
                //                                 sinfo.sinfo_cumtsn,
                //                                 sinfo.sinfo_assoc_id);

                // socket не потоковый, поэтому придется проверять assoc_id клиента - пришел новый ли и добавлять к существующим
                if (is_new_client(&client_list, sinfo.sinfo_assoc_id, &current_client)) {
                        printf("New client connected assoc_id %d!\n", sinfo.sinfo_assoc_id);
                        // для отправки личных сообщений сохраним структуру адресов каждого клиента
                        memcpy(&current_client->client_addr6, &client_addr6, sizeof(client_addr6));
                }

                if (!current_client->logged) {

                        char *word = strtok(buffer, " ");

                        if (!strcmp(word, "/login")) {

                                word = strtok(NULL, " \n");
                                if (word) {
                                        printf("[%d] New client: Username is %s len %ld\n", current_client->assoc_id, word, strlen(word));

                                        current_client->name = strdup(word);

                                        printf("[%d] login success: %s\n", current_client->assoc_id, current_client->name);
                                        
                                        // is registered?
                                        // password if yes, register if not
                                        if (search_user_db(current_client)) {
                                                printf("[%d] <%s> Client is registered in database, ask for password\n", current_client->assoc_id, current_client->name);
                                                sprintf(buffer, "[Server] Hello, %s.\n[Server] Please enter your password to continue: /passwd *password*\n", current_client->name);
                                                nread = strlen(buffer) + 1;
                                        
                                        } else {
                                                printf("[%d] <%s> Client is not in database, ask for password to register\n", current_client->assoc_id, current_client->name);
                                                sprintf(buffer, "[Server] Hello, you are new and need to register, your login is %s.\n[Server] Please type /passwd *password* to end registration and continue\n", current_client->name);
                                                nread = strlen(buffer) + 1;
                                        }

                                        current_client->logged = 1;

                                } else {
                                        printf("[%d]: login failed: no username\n", current_client->assoc_id);
                                        sprintf(buffer, "[Server] Please add your_name after login\n");
                                        nread = strlen(buffer) + 1;
                                }
                        } else {
                                sprintf(buffer, "[Server] Please type: /login *your_name*\n");
                                nread = strlen(buffer) + 1;
                        }

                        ret = sctp_sendmsg(sockfd, buffer, nread, (struct sockaddr *) &client_addr6, len, 0, 0, 0, 0, 0);
                        if (ret < 0)
                                die("sctp_sendmsg");


                        memset(buffer, 0, sizeof(buffer));

                        continue;
                }

                if (!current_client->registered) {
                        
                        char *word = strtok(buffer, " ");

                        if (!strcmp(word, "/passwd")) {

                                word = strtok(NULL, " \n");
                                if (word) {
                                        printf("[%d] <%s> New client: Password is %s len %ld\n", current_client->assoc_id, current_client->name, word, strlen(word));

                                        // Если пароль уже есть в базе данных
                                        if (current_client->pass) {
                                                printf("[%d] <%s> Client is registered check if password is correct\n", current_client->assoc_id, current_client->name);
                                                if (!strcmp(current_client->pass, word)) {
                                                        printf("[%d] <%s> Password is correct. Client is logged in\n", current_client->assoc_id, current_client->name);
                                                        current_client->registered = 1;
                                                        sprintf(buffer, "[Server] You have successfully logged in\n");
                                                        nread = strlen(buffer) + 1;
                                                } else {
                                                        printf("[%d] <%s> Password is wrong.\n", current_client->assoc_id, current_client->name);
                                                        sprintf(buffer, "[Server] Password is wrong. Try again: /passwd *password*\n");
                                                        nread = strlen(buffer) + 1;
                                                }

                                        } else {
                                                // Иначе регистрируем нового клиента и заносим запись в файл
                                                printf("[%d] <%s> New client! Register client in database\n", current_client->assoc_id, current_client->name);

                                                current_client->pass = strdup(word);

                                                register_new_client(current_client);
                                                current_client->registered = 1;
                                        
                                                sprintf(buffer, "[Server] You have successfully registered\n");
                                                nread = strlen(buffer) + 1;

                                        }


                                }

                        } else {
                                sprintf(buffer, "[Server] Please type: /passwd *password*\n");
                                nread = strlen(buffer) + 1;
                        }


                        ret = sctp_sendmsg(sockfd, buffer, nread, (struct sockaddr *) &client_addr6, len, 0, 0, 0, 0, 0);
                        if (ret < 0)
                                die("sctp_sendmsg");


                        memset(buffer, 0, sizeof(buffer));

                        continue;

                }

                
                // команды, доступны только после регистрации/логирования
                if (buffer[0] == '/' && sinfo.sinfo_stream == 0) {
                        
                        int cmd_found = 0;
                        // help message
                        char *cmd = strtok(buffer, " \n");
                        
                        if (!strcmp(cmd, "/help")) {
                                
                                sprintf(sendbuffer, HELP_MSG);
                                cmd_found = 1;
                        }

                        if (!cmd_found && !strcmp(cmd, "/m")) {

                                // имя пользователя будет в cmd
                                cmd = strtok(NULL, " \n");
                                if (cmd) {
                                        struct sockaddr_in6 client_addr2;
                                        printf("[%d] <%s> Private message to %s\n", current_client->assoc_id, current_client->name, cmd);

                                        if (find_user(client_list, cmd, &client_addr2)) {
                                                printf("[%d] <%s> Recipient found %s sending..\n", current_client->assoc_id, current_client->name, cmd);

                                                char *recipient_name = strdup(cmd);

                                                cmd = strtok(NULL, "");
                                                printf("[%d] Private message <%s> -> <%s>: %s", current_client->assoc_id, current_client->name, recipient_name, cmd);
                                                
                                                t = time(NULL);
                                                tm = *localtime(&t);
                                                sprintf(sendbuffer, "[%02d:%02d:%02d] <%s> -> <%s>: %s", tm.tm_hour, tm.tm_min, tm.tm_sec, current_client->name, recipient_name, cmd);
                                                nread = strlen(sendbuffer) + 1;

                                                free(recipient_name);

                                                ret = sctp_sendmsg(sockfd, sendbuffer, nread, (struct sockaddr *) &client_addr2, sizeof(client_addr2), 0, 0, 0, 0, 0);
                                                if (ret < 0)
                                                        die("sctp_sendmsg");


                                                
                                        } else {
                                                printf("[%d] <%s> Recipient not found\n", current_client->assoc_id, current_client->name);
                                                sprintf(sendbuffer, "[Server] Recipient not found. Try /list\n");
                                        }
                                } else {
                                        printf("[%d] <%s> Name not included in private message\n", current_client->assoc_id, current_client->name);
                                        sprintf(sendbuffer, "[Server] Name not included in private message. Usage: /m *user_name* message\n");
                                }

                                cmd_found = 1;
                        }
                
                        if (!cmd_found && !strcmp(cmd, "/list")) {

                                client_list_t *clientP = client_list;
                                memset(buffer, 0, sizeof(buffer));

                                while (clientP) { 
                                        // может быть переполнение
                                        sprintf(buffer, "%s\n[Server] %s", buffer, clientP->name);
                                        clientP = clientP->next_client;
                                }
                                sprintf(sendbuffer, "[Server] List of registered clients: %s\n", buffer);

                                cmd_found = 1;
                        }

                        if (!cmd_found && !strcmp(cmd, "/f")) {

                                cmd = strtok(NULL, " \n");
                                if (cmd) {
                                        printf("[%02d:%02d:%02d] [%d] <%s>: File %s, try to upload from client..\n", tm.tm_hour, tm.tm_min, tm.tm_sec, current_client->assoc_id, current_client->name, cmd);

                                        current_client->fname_upload = strdup(cmd);
                                        sprintf(sendbuffer, "/fsend %s", current_client->fname_upload);

                                        // не лучший вариант, если клиент постоянно будет посылать то, чего у него нету, 
                                        // то на сервере будут создваться пустые файлы и это может привести к переводу всех inode
                                        // поэтому удаляю получив fclose от клиента
                                        char path[48];
                                        sprintf(path, "Downloads/%s", current_client->fname_upload);
                                        current_client->fileP[0] = fopen(path, "wb");
                                        if (current_client->fileP[0] == NULL) {
                                                printf("[Server] Error creating file for client!\n");
                                                continue;
                                        }



                                } else {
                                        sprintf(sendbuffer, "[Server] To upload file to server enter filename: /f *file_name*\n");

                                }

                                cmd_found = 1;
                        }

                        if (!cmd_found && !strcmp(cmd, "/d")) {

                                cmd = strtok(NULL, " \n");
                                if (cmd) {

                                        char path[48];
                                        sprintf(path, "Downloads/%s", cmd);
                                        printf("[%d] <%s>: File %s, trying to send it to client..\n", current_client->assoc_id, current_client->name, cmd);

                                        current_client->fileP[1] = fopen(path, "rb");
                                        if (current_client->fileP[1] == NULL) {
                                                printf("[%d] <%s>: No such file or directory to download file %s\n", current_client->assoc_id, current_client->name, path);
                                                sprintf(sendbuffer, "[Server] No such file to download from server: %s\n", cmd);
                                                nread = strlen(sendbuffer) + 1;
                                                printf("nread %d\n", nread);
                                                ret = sctp_sendmsg(sockfd, sendbuffer, nread, (struct sockaddr *) &client_addr6, len, 0, 0, 2, 0, 0);
                                                if (ret < 0) {
                                                        printf("sctp_sendmsg()\n");
                                                        exit(1);
                                                }
                                                continue;
                                        }

                                        current_client->fname_dload = strdup(cmd);
                                        sprintf(sendbuffer, "/frecv %s", current_client->fname_dload);
                                        nread = strlen(sendbuffer) + 1;
                                        ret = sctp_sendmsg(sockfd, sendbuffer, nread, (struct sockaddr *) &client_addr6, len, 0, 0, 2, 0, 0);
                                        if (ret < 0) {
                                                printf("sctp_sendmsg()\n");
                                                exit(1);
                                        }

                                        printf("Server found file %s\n", path);
                                        
                                        // Отправка файла клиенту с сервера
                                        do {
                                                nread = fread(sendbuffer, 1, sizeof(sendbuffer), current_client->fileP[1]);
                                                printf("[%d] <%s>: Server sent %d bytes..\n", current_client->assoc_id, current_client->name, nread);

                                                ret = sctp_sendmsg(sockfd, sendbuffer, nread, (struct sockaddr *) &client_addr6, len, 0, 0, 2, 0, 0);
                                                if (ret < 0) {
                                                        printf("sctp_sendmsg()\n");
                                                        exit(1);
                                                }


                                        } while (nread == sizeof(sendbuffer));


                                        // Файл полностью отправили клиенту
                                        printf("[%d] <%s>: [Server] file downloaded: %s\n", current_client->assoc_id, current_client->name, current_client->fname_dload);
  

                                        free(current_client->fname_dload);
                                        fclose(current_client->fileP[1]);
                                        current_client->fname_dload = NULL;
                                        memset(buffer, 0, sizeof(buffer)); 

                                        continue;       


                                } else {
                                        sprintf(sendbuffer, "[Server] To download file from server need filename: /d *file_name*\n");

                                }
                                cmd_found = 1;
                        }

                        // на случай если клиент не нашел файл, который хотел отправить
                        if (!cmd_found && !strcmp(cmd, "/fclose")) {
                                
                                // небезопасно? :) нужна проверка на ../ иначе недобрый клиент удалит что-нибудь еще
                                char path[48];
                                sprintf(path, "Downloads/%s", current_client->fname_upload);
                                remove(path);
                                if (current_client->fileP[0]) fclose(current_client->fileP[0]);
                                if (current_client->fname_upload) free(current_client->fname_upload);

                                printf("[Server] closed fileP for [%d] <%s> path %s\n", current_client->assoc_id, current_client->name, path);
                                memset(buffer, 0, sizeof(buffer));
                                cmd_found = 1;
                                continue;
                        }

                        

                        // if (!cmd_found && !strcmp(cmd, "/exit")) {

                        //         cmd_found = 1;
                        // }


                        if (!cmd_found) {
                                sprintf(sendbuffer, "[Server] Command not found. Try /help\n");
                        }
                        
                        nread = strlen(sendbuffer) + 1;
                        ret = sctp_sendmsg(sockfd, sendbuffer, nread, (struct sockaddr *) &client_addr6, len, 0, 0, 0, 0, 0);
                        if (ret < 0)
                                die("sctp_sendmsg");


                        memset(buffer, 0, sizeof(buffer));

                        continue;
                }

                // 0 под чат, 1 stream под файлы (Загрузка на сервер)
                if (sinfo.sinfo_stream == 1) {
                        printf("[%d] <%s>: File recv %d bytes..\n", current_client->assoc_id, current_client->name, nread);
                        fwrite(buffer, 1, nread, current_client->fileP[0]);

                        // Отправим имя файла в чат когда файл полностью загрузится
                        if (nread != sizeof(buffer)) {
                                if (strstr(buffer, "/fclose")) {
                                        char path[48];
                                        sprintf(path, "Downloads/%s", current_client->fname_upload);
                                        remove(path);
                                        memset(buffer, 0, sizeof(buffer));
                                } else {
                                        // Файл был загружен на сервер
                                        t = time(NULL);
                                        tm = *localtime(&t);
                                        sprintf(buffer, "(file): %s\n", current_client->fname_upload);
                                }
                                free(current_client->fname_upload);
                                fclose(current_client->fileP[0]);
                                current_client->fname_upload = NULL;

                                
                        } else {

                                continue;
                        }

                }


                if (nread > 0) {
                        printf("%s", buffer);
                        fflush(stdout);
                }


                bzero(&sinfo, sizeof(sinfo));
                sinfo.sinfo_flags |= SCTP_SENDALL;
               
                t = time(NULL);
                tm = *localtime(&t);

                printf("[%02d:%02d:%02d] [%d] <%s>:", tm.tm_hour, tm.tm_min, tm.tm_sec, current_client->assoc_id, current_client->name);

                sprintf(sendbuffer, "[%02d:%02d:%02d] <%s>: %s", tm.tm_hour, tm.tm_min, tm.tm_sec, current_client->name, buffer);
                nread = strlen(sendbuffer) + 1;

                // Всем подклюенным пользователям
                sctp_send(sockfd, sendbuffer, nread,
                                  &sinfo, 0);

                
                memset(buffer, 0, sizeof(buffer));
                memset(sendbuffer, 0, sizeof(sendbuffer));

        }

        // pthread_join(thread_id, NULL);
        close(sockfd);

        return 0;
}
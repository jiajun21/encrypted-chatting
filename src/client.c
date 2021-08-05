#include "protocol.h"
#include "secure.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

static char * path;
static char username[64];
static int channel;
static unsigned char key[32];
static unsigned char iv[16];

static void start_routine(void);

int main(int argc, char * argv[])
{
    int client_sock;
    struct sockaddr_in server_addr;

    secure_init_client();

    client_sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &(server_addr.sin_addr));

    connect(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    channel = client_sock;
    start_routine();

    secure_finish_client();

    return 0;
}

static int _get_int(int * addr)
{
    char c;
    int ret;

    ret = scanf("%d", addr);
    if (ret == 1)
        ret = 0;
    else
        ret = -1;
    while ((c = getchar()) != '\n' && c != EOF);

    return ret;
}

static int _get_string(char * buf, int max_size)
{
    char c;
    int index;
    int ret;

    for (index = 0; index < max_size; index++)
    {
        c = getchar();
        if (c == '\n')
            break;
        buf[index] = c;
    }
    if (c == '\n')
        ret = 0;
    else
    {
        ret = -1;
        while ((c = getchar()) != '\n' && c != EOF);
        index--;
    }
    buf[index] = '\0';

    return ret;
}

static int _recv_friendlist(void)
{
    char buf[512];

    printf("   STATE   USERNAME\n");
    while (1)
    {
        secure_recv(channel, buf, 66, 0, key, iv);

        if (buf[0] == PROTO_F_LIST_END)
            break;

        switch (buf[65])
        {
        case TABLE_F_STATE_SEND:
            printf("   [send]  %s\n", &(buf[1]));
            break;
        case TABLE_F_STATE_RECV:
            printf("   [recv]  %s\n", &(buf[1]));
            break;
        case TABLE_F_STATE_BEING:
            printf("   [being] %s\n", &(buf[1]));
            break;
        default:
            printf("   [???]   %s\n", &(buf[1]));
            break;
        }
    }

    return 0;
}

static int _recv_messagelist(FILE * file, int flag)
{
    char buf[1024];
    char time_string[26];
    char mark;
    time_t time;

    while (1)
    {
        secure_recv(channel, buf, 878, 0, key, iv);

        if (buf[0] == PROTO_M_LIST_END)
            break;
        if (buf[0] == PROTO_FINISH)
            return -1;

        if (flag)
        {
            if (buf[1] == TABLE_M_STATE_UNREAD
                         && strcmp(username, &(buf[10])) != 0)
                mark = 'u';
            else
                mark = ' ';
        }
        else
        {
            if (strcmp(username, &(buf[10])) == 0)
                mark = '>';
            else
                mark = '<';
        }
        time = (time_t)*((double *)&(buf[2]));
        ctime_r(&time, time_string);
        time_string[19] = '\0';
        time_string[24] = '\0';

        fprintf(file, "%c [%s %s]      %s\n",
                    mark, &(time_string[20]), &(time_string[4]), &(buf[10]));
        fprintf(file, "    %s\n", &(buf[74]));
        fprintf(file, "\n");
        fflush(file);
        fsync(fileno(file));
    }

    return 0;
}

static void * r_thread_routine(void * arg)
{
    FILE * file;
    int ret;

    file = arg;

    fprintf(file, "\n");
    _recv_messagelist(file, 1);

    fprintf(file, "\n");
    fprintf(file, "-------- history ('u' for unread) --------\n");
    fprintf(file, "\n");
    fflush(file);
    fsync(fileno(file));

    while (1)
    {
        ret = _recv_messagelist(file, 0);
        if (ret == -1)
            break;
    }

    return NULL;
}

static void * w_thread_routine(void * arg)
{
    struct timeval tv;
    char buf[1024];

    printf("> execute \"tail -n +1 -f %s/%s\" in another terminal\n", path, CLIENT_CHATFILE);
    printf("  type \"\\quit\" to quit\n");
    printf("\n");

    while (1)
    {
        printf("# ");
        _get_string(&(buf[9]), 804);

        if (strcmp(&(buf[9]), "\\quit") == 0)
        {
            system("clear");
            buf[0] = PROTO_FINISH;
            secure_send(channel, buf, 813, 0, key, iv);
            break;
        }

        buf[0] = PROTO_CHAT_MESSAGE;
        gettimeofday(&tv, NULL);
        *((double *)&(buf[1])) = tv.tv_sec + (double)tv.tv_usec / 1000000;

        secure_send(channel, buf, 813, 0, key, iv);
    }

    return NULL;
}

static void _pause(void)
{
    char c;

    printf("press ENTER to continue...");
    while ((c = getchar()) != '\n' && c != EOF);
}

static int _init(void)
{
    int path_len;
    int ret;

    secure_build_key_client(channel, key, iv);

    path_len = 128;
    while (1)
    {
        path = (char *)malloc(path_len);
        if (NULL != getcwd(path, path_len))
        {
            ret = 0;
            break;
        }
        else
        {
            free(path);
            if (ERANGE == errno)
                path_len *= 2;
            else
            {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}

static void _welcome(void)
{
    printf("\n");
    printf("Welcome to Encrypted Chatting!\n");
    printf("\n");
}

static void _help(int chapter)
{
    switch (chapter)
    {
    case 1:
        printf("   sign in and sign up: \n");
        printf("   1. input \"username\" & \"password\"\n");
        printf("   2. \"username\" should not exceed 15 characters\n");
        printf("   3. \"username\" should only use chinese characters, english\n");
        printf("      characters and '_'\n");
        printf("   4. \"password\" should not exceed 30 characters\n");
        break;
    case 2:
        printf("   mode selection:\n");
        printf("   1. chat mode: select a friend of yours to chat with\n");
        printf("   2. span mode: add new friends or accept/reject invitations\n");
        break;
    case 3:
        printf("   chat mode:\n");
        printf("   1. select a friend, type message and send\n");
        printf("   2. message should not exceed 200 characters\n");
        printf("   3. to view the chat box, you need to open a new terminal\n");
        printf("      and execute \"tail -n +1 -f %s/%s\"\n", path, CLIENT_CHATFILE);
        printf("   4. when chatting, input \"\\quit\" to quit\n");
        break;
    case 4:
        printf("   span mode:\n");
        printf("   1. add new friends, accept invitations, or reject\n");
        printf("   2. friend has 3 states: send & recv & being\n");
        printf("      send state: you have added he/she, but he/she has not responded yet\n");
        printf("      recv state: he/she is waiting for your respond\n");
        printf("      being state: being friend! you both can chat with each other\n");
        break;
    default:
        printf("   hi!\n");
        break;
    }

    printf("\n");
    printf("   ");
    _pause();
    system("clear");
}

static int _sign_in(void)
{
    char send_buf[512];
    char recv_buf[512];
    int ret;

    send_buf[0] = PROTO_SIGN_IN;
    printf(">> username: ");
    _get_string(&(send_buf[1]), 64);
    printf("   password: ");
    _get_string(&(send_buf[65]), 124);
    printf("\n");

    secure_send(channel, send_buf, 189, 0, key, iv);
    secure_recv(channel, recv_buf, 1, 0, key, iv);

    switch (recv_buf[0])
    {
    case PROTO_OK:
        ret = 0;
        strcpy(username, &(send_buf[1]));
        break;
    case PROTO_ERROR_INCORRECT:
        ret = -1;
        printf("   [error]: password is incorrect, ");
        _pause();
        break;
    case PROTO_ERROR_NOTEXIST:
        ret = -1;
        printf("   [error]: username does not exist, ");
        _pause();
        break;
    default:
        ret = -1;
        printf("   [error]: unknown, ");
        _pause();
        break;
    }

    system("clear");

    return ret;
}

static int _sign_up(void)
{
    char send_buf[512];
    char recv_buf[512];
    int start_flag;
    int ret;

    send_buf[0] = PROTO_SIGN_UP;
    start_flag = 1;
    while (1)
    {
        if (start_flag)
        {
            start_flag = 0;
            printf(">> username: ");
        }
        else
            printf("   username: ");
        ret = _get_string(&(send_buf[1]), 64);
        if (ret == 0)
            break;
        else
            printf("   [error]: username should not exceed 15 characters\n");
    }
    while (1)
    {
        printf("   password: ");
        ret = _get_string(&(send_buf[65]), 124);
        if (ret == 0)
            break;
        else
            printf("   [error]: password should not exceed 30 characters\n");
    }
    printf("\n");

    secure_send(channel, send_buf, 189, 0, key, iv);
    secure_recv(channel, recv_buf, 1, 0, key, iv);

    switch (recv_buf[0])
    {
    case PROTO_OK:
        ret = 0;
        strcpy(username, &(send_buf[1]));
        break;
    case PROTO_ERROR_EXIST:
        ret = -1;
        printf("   [error]: username exists, ");
        _pause();
        break;
    default:
        ret = -1;
        printf("   [error]: unknown, ");
        _pause();
        break;
    }

    system("clear");

    return ret;
}

static void _chat(void)
{
    pthread_t rw_threads[2];
    FILE * file;
    char buf[1024];
    int choice;
    int ret;

    buf[0] = PROTO_CHAT;
    secure_send(channel, buf, 1, 0, key, iv);
    system("clear");

    while (1)
    {
        _recv_friendlist();
        printf("\n");
        printf(">> 1. select\n");
        printf("   2. help [!important]\n");
        printf("   3. back\n");
        printf("<< ");
        ret = _get_int(&choice);

        if (ret == -1)
        {
            printf("\n");
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            buf[0] = PROTO_CONTINUE;
            secure_send(channel, buf, 65, 0, key, iv);
            continue;
        }

        switch (choice)
        {
        case 1:
            printf("   username: ");
            buf[0] = PROTO_CHAT_OPTION_SEL;
            _get_string(&(buf[1]), 64);
            printf("\n");

            secure_send(channel, buf, 65, 0, key, iv);
            secure_recv(channel, buf, 1, 0, key, iv);

            switch (buf[0])
            {
            case PROTO_OK:
                system("clear");
                file = fopen(CLIENT_CHATFILE, "w");
                pthread_create(&(rw_threads[0]), NULL,
                            r_thread_routine, file);
                pthread_create(&(rw_threads[1]), NULL,
                            w_thread_routine, NULL);
                pthread_join(rw_threads[1], NULL);
                // pthread_cancel(rw_threads[0]);
                pthread_join(rw_threads[0], NULL);
                fclose(file);
                break;
            case PROTO_ERROR_INCORRECT:
                printf("   [error]: username is invalid, ");
                _pause();
                break;
            default:
                printf("   [error]: unknown, ");
                _pause();
                break;
            }
            system("clear");
            break;
        case 2:
            printf("\n");
            _help(3);
            buf[0] = PROTO_CONTINUE;
            secure_send(channel, buf, 65, 0, key, iv);
            break;
        case 3:
            system("clear");
            buf[0] = PROTO_FINISH;
            secure_send(channel, buf, 65, 0, key, iv);
            return;
            // break;
        default:
            printf("\n");
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            buf[0] = PROTO_CONTINUE;
            secure_send(channel, buf, 65, 0, key, iv);
            break;
        }
    }
}

static void _span(void)
{
    char buf[1024];
    int choice;
    int ret;

    buf[0] = PROTO_SPAN;
    secure_send(channel, buf, 1, 0, key, iv);
    system("clear");

    while (1)
    {
        _recv_friendlist();
        printf("\n");
        printf(">> 1. add\n");
        printf("   2. accept\n");
        printf("   3. reject\n");
        printf("   4. help\n");
        printf("   5. back\n");
        printf("<< ");
        ret = _get_int(&choice);

        if (ret == -1)
        {
            printf("\n");
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            buf[0] = PROTO_CONTINUE;
            secure_send(channel, buf, 65, 0, key, iv);
            continue;
        }

        switch (choice)
        {
        case 1:
            printf("   username: ");
            buf[0] = PROTO_SPAN_OPTION_ADD;
            _get_string(&(buf[1]), 64);
            printf("\n");

            secure_send(channel, buf, 65, 0, key, iv);
            secure_recv(channel, buf, 1, 0, key, iv);

            switch (buf[0])
            {
            case PROTO_OK:
                break;
            case PROTO_ERROR_NOTEXIST:
                printf("   [error]: username does not exist, ");
                _pause();
                break;
            case PROTO_ERROR_INCORRECT:
                printf("   [error]: username is invalid, ");
                _pause();
                break;
            default:
                printf("   [error]: unknown, ");
                _pause();
                break;
            }
            system("clear");
            break;
        case 2:
            printf("   username: ");
            buf[0] = PROTO_SPAN_OPTION_ACC;
            _get_string(&(buf[1]), 64);
            printf("\n");

            secure_send(channel, buf, 65, 0, key, iv);
            secure_recv(channel, buf, 1, 0, key, iv);

            switch (buf[0])
            {
            case PROTO_OK:
                break;
            case PROTO_ERROR_INCORRECT:
                printf("   [error]: username is invalid, ");
                _pause();
                break;
            default:
                printf("   [error]: unknown, ");
                _pause();
                break;
            }
            system("clear");
            break;
        case 3:
            printf("   username: ");
            buf[0] = PROTO_SPAN_OPTION_REJ;
            _get_string(&(buf[1]), 64);
            printf("\n");

            secure_send(channel, buf, 65, 0, key, iv);
            secure_recv(channel, buf, 1, 0, key, iv);

            switch (buf[0])
            {
            case PROTO_OK:
                break;
            case PROTO_ERROR_INCORRECT:
                printf("   [error]: username is invalid, ");
                _pause();
                break;
            default:
                printf("   [error]: unknown, ");
                _pause();
                break;
            }
            system("clear");
            break;
        case 4:
            printf("\n");
            _help(4);
            buf[0] = PROTO_CONTINUE;
            secure_send(channel, buf, 65, 0, key, iv);
            break;
        case 5:
            system("clear");
            buf[0] = PROTO_FINISH;
            secure_send(channel, buf, 65, 0, key, iv);
            return;
            // break;
        default:
            printf("\n");
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            buf[0] = PROTO_CONTINUE;
            secure_send(channel, buf, 65, 0, key, iv);
            break;
        }
    }
}

static void start_routine(void)
{
    char buf[1024];
    int choice;
    int ret;

    _init();

    _welcome();

    while (1)
    {
        printf(">> 1. sign in\n");
        printf("   2. sign up\n");
        printf("   3. help\n");
        printf("   4. quit\n");
        printf("<< ");
        ret = _get_int(&choice);
        printf("\n");

        if (ret == -1)
        {
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            continue;
        }

        switch (choice)
        {
        case 1:
            ret = _sign_in();
            if (ret == 0)
                goto online;
            break;
        case 2:
            ret = _sign_up();
            if (ret == 0)
                goto online;
            break;
        case 3:
            _help(1);
            break;
        case 4:
            buf[0] = PROTO_DISCONNECT;
            secure_send(channel, buf, 189, 0, key, iv);
            goto quit;
            // break;
        default:
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            break;
        }
    }

online:
    while (1)
    {
        printf(">> 1. chat mode\n");
        printf("   2. span mode\n");
        printf("   3. help\n");
        printf("   4. quit\n");
        printf("<< ");
        ret = _get_int(&choice);
        printf("\n");

        if (ret == -1)
        {
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            continue;
        }

        switch (choice)
        {
        case 1:
            _chat();
            break;
        case 2:
            _span();
            break;
        case 3:
            _help(2);
            break;
        case 4:
            buf[0] = PROTO_DISCONNECT;
            secure_send(channel, buf, 1, 0, key, iv);
            goto quit;
            // break;
        default:
            printf("   [error]: input is incorrect, ");
            _pause();
            system("clear");
            break;
        }
    }

quit:
    free(path);
    close(channel);
}

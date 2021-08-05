#include "protocol.h"
#include "log.h"
#include "secure.h"
#include "database.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct thread_info
{
    pthread_t thread;
    int channel;
};

struct rw_thread_info
{
    pthread_t thread;
    char * username;
    char * peername;
    // MYSQL * mysql;
    // pthread_mutex_t * database_mutex;
    int channel;
    unsigned char * key;
    unsigned char * iv;
    int64_t message_id;
    int * finish;
    pthread_mutex_t * finish_mutex;
};

static sem_t thread_sem;
static pthread_mutex_t thread_freeflag_mutex;
static int thread_freeflag[SERVER_MAX_CLIENT_NUM] = {0};
static struct thread_info threads[SERVER_MAX_CLIENT_NUM];

static void * thread_start_routine(void * arg);

int main(int argc, char ** argv)
{
    int server_sock, channel;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addrlen;
    int thread_index;

    log_init();
    secure_init_server();
    database_init();
    sem_init(&thread_sem, 0, SERVER_MAX_CLIENT_NUM);
    pthread_mutex_init(&thread_freeflag_mutex, NULL);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &(server_addr.sin_addr));
    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    listen(server_sock, 10);

    log_print(LOG_INFO, "[server]: server starts");

    while (1)
    {
        sem_wait(&thread_sem);
        pthread_mutex_lock(&thread_freeflag_mutex);
        for (int i = 0; i < SERVER_MAX_CLIENT_NUM; i++)
        {
            if (thread_freeflag[i] == 0)
            {
                thread_index = i;
                thread_freeflag[i] = 1;
                break;
            }
        }
        pthread_mutex_unlock(&thread_freeflag_mutex);
        addrlen = sizeof(client_addr);
        channel = accept(server_sock,
                            (struct sockaddr *)&client_addr,
                            &addrlen);
        log_print(LOG_INFO, "[server]: establish connection with: %s:%hu",
                            inet_ntoa(client_addr.sin_addr),
                            ntohs(client_addr.sin_port));
        threads[thread_index].channel = channel;
        pthread_create(&(threads[thread_index].thread),
                        NULL,
                        thread_start_routine,
                        &(threads[thread_index]));
    }

    close(server_sock);
    pthread_mutex_destroy(&thread_freeflag_mutex);
    sem_destroy(&thread_sem);
    database_finish();
    secure_finish_server();
    log_finish();

    return 0;
}

static int _database_check(MYSQL * mysql)
{
    int ret;

    ret = database_table_exist(mysql, "user");
    if (ret != 0)
    {
        database_create_table(mysql, "user",
                    "username varchar(64) charset utf8 not null primary key,\
                    password varchar(124) charset utf8 not null");
    }

    return 0;
}

static int _database_exist(MYSQL * mysql, const char * table,
                                        const char * constraint)
{
    MYSQL_RES * result;
    int ret;

    database_select(mysql, table, "*", constraint);
    result = database_get_result(mysql);
    if (result == NULL)
        ret = -2;
    else
    {
        if (0 == database_get_row_num(result))
            ret = -1;
        else
            ret = 0;
    }
    database_free_result(result);

    return ret;
}

static int _sign_in(MYSQL * mysql, const char * username, const char * password)
{
    MYSQL_RES * result;
    MYSQL_ROW row;
    char constraint[128];
    int ret;

    snprintf(constraint, 128, "where username=\"%s\"", username);
    ret = _database_exist(mysql, "user", constraint);
    if (ret != 0)
        ret = -2;
    else
    {
        database_select(mysql, "user", "password", constraint);
        result = database_get_result(mysql);
        row = database_get_row(result);
        if (strcmp(password, row[0]) != 0)
            ret = -1;
        else
            ret = 0;
        database_free_result(result);
    }

    return ret;
}

static int _sign_up(MYSQL * mysql, const char * username, const char * password)
{
    char buf[256];
    int ret;

    snprintf(buf, 256, "where username=\"%s\"", username);
    ret = _database_exist(mysql, "user", buf);
    if (ret == 0)
        ret = -1;
    else
    {
        snprintf(buf, 256, "\"%s\", \"%s\"", username, password);
        database_insert(mysql, "user", "username, password", buf);
        snprintf(buf, 256, "%s_friend", username);
        database_create_table(mysql, buf,
                "username varchar(64) charset utf8 not null primary key,\
                state tinyint not null");
        ret = 0;
    }

    return ret;
}

static int _send_friendlist(MYSQL * mysql, const char * username,
                                            int channel,
                                            const unsigned char * key,
                                            const unsigned char * iv,
                                            int flag)
{
    MYSQL_RES * result;
    MYSQL_ROW row;
    char table[128];
    char buf[1024];
    int state;
    int ret;

    snprintf(table, 128, "%s_friend", username);
    database_select(mysql, table, "*", "");
    result = database_get_result(mysql);
    if (result == NULL)
        ret = -1;
    else
    {
        while ((row = database_get_row(result)))
        {
            state = atoi(row[1]);
            if (state & flag)
            {
                buf[0] = PROTO_F_LIST;
                strcpy(&(buf[1]), row[0]);
                buf[65] = (char)state;
                secure_send(channel, buf, 66, 0, key, iv);
            }
        }
        buf[0] = PROTO_F_LIST_END;
        secure_send(channel, buf, 66, 0, key, iv);
        ret = 0;
    }
    database_free_result(result);

    return ret;
}

static int _send_messagelist(MYSQL * mysql, const char * username,
                                            const char * peername,
                                            int channel,
                                            const unsigned char * key,
                                            const unsigned char * iv,
                                            int64_t * message_id)
{
    MYSQL_RES * result;
    MYSQL_ROW row;
    char buf[1024];
    char table[256];
    char constraint[128];
    char todo[128];
    int64_t this_id;
    int ret;

    ret = strcmp(username, peername);
    snprintf(table, 256, "%s_%s_message",
                        (ret < 0) ? username : peername,
                        (ret < 0) ? peername : username);
    snprintf(constraint, 128, "where id>%ld order by time", *message_id);
    database_select(mysql, table, "*", constraint);
    result = database_get_result(mysql);
    if (result == NULL)
        ret = -1;
    else
    {
        while ((row = database_get_row(result)))
        {
            buf[0] = PROTO_M_LIST;
            buf[1] = (char)atoi(row[1]);
            *((double *)&(buf[2])) = atof(row[2]);
            strcpy(&(buf[10]), row[3]);
            strcpy(&(buf[74]), row[4]);
            secure_send(channel, buf, 878, 0, key, iv);

            this_id = atoll(row[0]);
            if (this_id > *message_id)
                *message_id = this_id;
            if (atoi(row[1]) == TABLE_M_STATE_UNREAD && strcmp(row[3], peername) == 0)
            {
                snprintf(todo, 128, "state=%d", TABLE_M_STATE_READ);
                snprintf(constraint, 128, "where id=%ld", this_id);
                database_update(mysql, table, todo, constraint);
            }
        }
        buf[0] = PROTO_M_LIST_END;
        secure_send(channel, buf, 878, 0, key, iv);
        ret = 0;
    }
    database_free_result(result);

    return ret;
}

static void * r_thread_routine(void * arg)
{
    struct rw_thread_info * info;
    MYSQL * mysql;
    char buf[1024];
    char table[256];
    char value[2048];
    int ret;

    info = arg;
    mysql = database_connect();

    ret = strcmp(info->username, info->peername);
    snprintf(table, 256, "%s_%s_message",
                        (ret < 0) ? info->username : info->peername,
                        (ret < 0) ? info->peername : info->username);

    // database_thread_init();
    while (1)
    {
        ret = secure_recv(info->channel, buf, 813, 0, info->key, info->iv);

        if (ret == -1 || buf[0] == PROTO_FINISH)
            break;

        snprintf(value, 2048, "NULL, %d, %lf, \"%s\", \"%s\"",
                                TABLE_M_STATE_UNREAD,
                                *((double *)&(buf[1])),
                                info->username,
                                &(buf[9]));

        // pthread_mutex_lock(info->database_mutex);
        database_insert(mysql, table, "id, state, time, username, message", value);
        // pthread_mutex_unlock(info->database_mutex);
    }
    // database_thread_finish();

    database_disconnect(mysql);

    if (ret == -1)
        return (void *)-1;
    else
        return (void *)0;
}

static void * w_thread_routine(void * arg)
{
    struct rw_thread_info * info;
    MYSQL * mysql;
    char buf[1024];
    int finish;

    info = arg;
    mysql = database_connect();
    finish = 0;

    // database_thread_init();
    while (1)
    {
        // pthread_mutex_lock(info->database_mutex);
        _send_messagelist(mysql, info->username, info->peername,
                            info->channel, info->key, info->iv,
                            &(info->message_id));
        // pthread_mutex_unlock(info->database_mutex);

        pthread_mutex_lock(info->finish_mutex);
        if (1 == *(info->finish))
            finish = 1;
        pthread_mutex_unlock(info->finish_mutex);
        if (finish)
            break;
        sleep(SERVER_CHAT_SYN_INTERVAL);
    }
    // database_thread_finish();

    buf[0] = PROTO_FINISH;
    secure_send(info->channel, buf, 878, 0, info->key, info->iv);

    database_disconnect(mysql);

    return NULL;
}

static int _chat(MYSQL * mysql, const char * username,
                                int channel,
                                const unsigned char * key,
                                const unsigned char * iv)
{
    char buf[1024];
    char table[128];
    char constraint[2048];
    char peername[64];
    int64_t message_id;
    struct rw_thread_info rw_threads[2];
    // pthread_mutex_t database_mutex;
    pthread_mutex_t finish_mutex;
    int finish;
    int ret;

    while (1)
    {
        _send_friendlist(mysql, username, channel, key, iv, TABLE_F_STATE_BEING);
        ret = secure_recv(channel, buf, 65, 0, key, iv);
        if (ret == -1)
            return -1;

        if (buf[0] == PROTO_FINISH)
            break;
        if (buf[0] == PROTO_CONTINUE)
            continue;

        switch (buf[0])
        {
        case PROTO_CHAT_OPTION_SEL:
            snprintf(table, 128, "%s_friend", username);
            snprintf(constraint, 2048, "where username=\"%s\" and state=%d",
                                            &(buf[1]), TABLE_F_STATE_BEING);
            ret = _database_exist(mysql, table, constraint);
            if (ret == 0)
            {
                buf[0] = PROTO_OK;
                strcpy(peername, &(buf[1]));
            }
            else
                buf[0] = PROTO_ERROR_INCORRECT;
            secure_send(channel, buf, 1, 0, key, iv);
            if (ret == 0)
            {
                log_print(LOG_INFO, "[%s]: send message to %s", username, peername);
                message_id = 0;
                _send_messagelist(mysql, username, peername,
                                channel, key, iv, &message_id);
                // pthread_mutex_init(&database_mutex, NULL);
                pthread_mutex_init(&finish_mutex, NULL);
                finish = 0;
                rw_threads[0].username = (char *)username;
                rw_threads[0].peername = peername;
                // rw_threads[0].mysql = mysql;
                // rw_threads[0].database_mutex = &database_mutex;
                rw_threads[0].channel = channel;
                rw_threads[0].key = (unsigned char *)key;
                rw_threads[0].iv = (unsigned char *)iv;
                rw_threads[0].message_id = 0;
                rw_threads[0].finish = NULL;
                rw_threads[0].finish_mutex = NULL;
                rw_threads[1].username = (char *)username;
                rw_threads[1].peername = peername;
                // rw_threads[1].mysql = mysql;
                // rw_threads[1].database_mutex = &database_mutex;
                rw_threads[1].channel = channel;
                rw_threads[1].key = (unsigned char *)key;
                rw_threads[1].iv = (unsigned char *)iv;
                rw_threads[1].message_id = message_id;
                rw_threads[1].finish = &finish;
                rw_threads[1].finish_mutex = &finish_mutex;
                pthread_create(&(rw_threads[0].thread), NULL,
                                r_thread_routine, &(rw_threads[0]));
                pthread_create(&(rw_threads[1].thread), NULL,
                                w_thread_routine, &(rw_threads[1]));
                pthread_join(rw_threads[0].thread, (void **)&ret);
                if (ret == -1)
                    pthread_cancel(rw_threads[1].thread);
                else
                {
                    pthread_mutex_lock(&finish_mutex);
                    finish = 1;
                    pthread_mutex_unlock(&finish_mutex);
                }
                pthread_join(rw_threads[1].thread, NULL);
                pthread_mutex_destroy(&finish_mutex);
                // pthread_mutex_destroy(&database_mutex);
                if (ret == -1)
                    return -1;
            }
            break;
        default:
            buf[0] = PROTO_ERROR_UNKNOWN;
            secure_send(channel, buf, 1, 0, key, iv);
            break;
        }
    }

    return 0;
}

static int _span_add(MYSQL * mysql,
                    const char * username,
                    const char * peername)
{
    char table[128];
    char constraint[128];
    char value[128];
    int ret;

    snprintf(constraint, 128, "where username=\"%s\"", peername);
    ret = _database_exist(mysql, "user", constraint);
    if (ret != 0)
        ret = -1;
    else
    {
        snprintf(table, 128, "%s_friend", username);
        ret = _database_exist(mysql, table, constraint);
        if (ret == 0)
            ret = -2;
        else
        {
            snprintf(value, 128, "\"%s\", %d", peername, TABLE_F_STATE_SEND);
            database_insert(mysql, table, "username, state", value);
            snprintf(table, 128, "%s_friend", peername);
            snprintf(value, 128, "\"%s\", %d", username, TABLE_F_STATE_RECV);
            database_insert(mysql, table, "username, state", value);
            ret = 0;
        }
    }

    return ret;
}

static int _span_accept(MYSQL * mysql,
                        const char * username,
                        const char * peername)
{
    char table[256];
    char constraint[128];
    char todo[32];
    int ret;

    snprintf(table, 256, "%s_friend", username);
    snprintf(constraint, 128, "where username=\"%s\" and state=%d",
                                peername, TABLE_F_STATE_RECV);
    ret = _database_exist(mysql, table, constraint);
    if (ret != 0)
        ret = -1;
    else
    {
        snprintf(todo, 32, "state=%d", TABLE_F_STATE_BEING);
        snprintf(constraint, 128, "where username=\"%s\"", peername);
        database_update(mysql, table, todo, constraint);
        snprintf(table, 256, "%s_friend", peername);
        snprintf(constraint, 128, "where username=\"%s\"", username);
        database_update(mysql, table, todo, constraint);
        ret = strcmp(username, peername);
        snprintf(table, 256, "%s_%s_message",
                        (ret < 0) ? username : peername,
                        (ret < 0) ? peername : username);
        database_create_table(mysql, table,
                    "id bigint not null auto_increment primary key,\
                    state tinyint not null,\
                    time double not null,\
                    username varchar(64) charset utf8 not null,\
                    message varchar(804) charset utf8");
        ret = 0;
    }

    return ret;
}

static int _span_reject(MYSQL * mysql,
                        const char * username,
                        const char * peername)
{
    char table[128];
    char constraint[128];
    int ret;

    snprintf(table, 128, "%s_friend", username);
    snprintf(constraint, 128, "where username=\"%s\" and state=%d",
                                peername, TABLE_F_STATE_RECV);
    ret = _database_exist(mysql, table, constraint);
    if (ret != 0)
        ret = -1;
    else
    {
        database_delete(mysql, table, constraint);
        snprintf(table, 128, "%s_friend", peername);
        snprintf(constraint, 128, "where username=\"%s\"", username);
        database_delete(mysql, table, constraint);
        ret = 0;
    }

    return ret;
}

static int _span(MYSQL * mysql, const char * username,
                                int channel,
                                const unsigned char * key,
                                const unsigned char * iv)
{
    char buf[1024];
    int ret;

    while (1)
    {
        _send_friendlist(mysql, username, channel, key, iv,
                TABLE_F_STATE_SEND | TABLE_F_STATE_RECV | TABLE_F_STATE_BEING);
        ret = secure_recv(channel, buf, 65, 0, key, iv);
        if (ret == -1)
            return -1;

        if (buf[0] == PROTO_FINISH)
            break;
        if (buf[0] == PROTO_CONTINUE)
            continue;

        switch (buf[0])
        {
        case PROTO_SPAN_OPTION_ADD:
            ret = _span_add(mysql, username, &(buf[1]));
            if (ret == 0)
            {
                log_print(LOG_INFO, "[%s]: add %s", username, &(buf[1]));
                buf[0] = PROTO_OK;
            }
            else if (ret == -1)
                buf[0] = PROTO_ERROR_NOTEXIST;
            else if (ret == -2)
                buf[0] = PROTO_ERROR_INCORRECT;
            else
                buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        case PROTO_SPAN_OPTION_ACC:
            ret = _span_accept(mysql, username, &(buf[1]));
            if (ret == 0)
            {
                log_print(LOG_INFO, "[%s]: accept %s", username, &(buf[1]));
                buf[0] = PROTO_OK;
            }
            else if (ret == -1)
                buf[0] = PROTO_ERROR_INCORRECT;
            else
                buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        case PROTO_SPAN_OPTION_REJ:
            ret = _span_reject(mysql, username, &(buf[1]));
            if (ret == 0)
            {
                log_print(LOG_INFO, "[%s]: reject %s", username, &(buf[1]));
                buf[0] = PROTO_OK;
            }
            else if (ret == -1)
                buf[0] = PROTO_ERROR_INCORRECT;
            else
                buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        default:
            buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        }
        secure_send(channel, buf, 1, 0, key, iv);
    }

    return 0;
}

static void * thread_start_routine(void * arg)
{
    struct thread_info * info;
    unsigned char key[32];
    unsigned char iv[16];
    MYSQL * mysql;
    int online;
    char buf[1024];
    char username[64];
    int ret;

    info = arg;

    if (info->channel == -1)
        goto clean;

    secure_build_key_server(info->channel, key, iv);
    mysql = database_connect();
    _database_check(mysql);
    online = 0;

    while (online == 0)
    {
        ret = secure_recv(info->channel, buf, 189, 0, key, iv);
        if (ret == -1)
            goto disconnect;

        if (buf[0] == PROTO_DISCONNECT)
            goto disconnect;

        switch (buf[0])
        {
        case PROTO_SIGN_IN:
            ret = _sign_in(mysql, &(buf[1]), &(buf[65]));
            if (ret == 0)
            {
                buf[0] = PROTO_OK;
                strcpy(username, &(buf[1]));
                online = 1;
            }
            else if (ret == -1)
                buf[0] = PROTO_ERROR_INCORRECT;
            else if (ret == -2)
                buf[0] = PROTO_ERROR_NOTEXIST;
            else
                buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        case PROTO_SIGN_UP:
            ret = _sign_up(mysql, &(buf[1]), &(buf[65]));
            if (ret == 0)
            {
                buf[0] = PROTO_OK;
                strcpy(username, &(buf[1]));
                online = 1;
            }
            else if (ret == -1)
                buf[0] = PROTO_ERROR_EXIST;
            else
                buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        default:
            buf[0] = PROTO_ERROR_UNKNOWN;
            break;
        }
        secure_send(info->channel, buf, 1, 0, key, iv);
    }

    log_print(LOG_INFO, "[%s]: hello, world!", username);

    while (1)
    {
        ret = secure_recv(info->channel, buf, 1, 0, key, iv);
        if (ret == -1)
            goto disconnect;

        if (buf[0] == PROTO_DISCONNECT)
            goto disconnect;

        switch (buf[0])
        {
        case PROTO_CHAT:
            ret = _chat(mysql, username, info->channel, key, iv);
            if (ret == -1)
                goto disconnect;
            break;
        case PROTO_SPAN:
            _span(mysql, username, info->channel, key, iv);
            break;
        default:
            /* error */
            break;
        }
    }

disconnect:
    if (online)
        log_print(LOG_INFO, "[%s]: bye!", username);
    database_disconnect(mysql);
    close(info->channel);
    info->channel = -1;
clean:
    pthread_mutex_lock(&thread_freeflag_mutex);
    thread_freeflag[info - threads] = 0;
    pthread_mutex_unlock(&thread_freeflag_mutex);
    sem_post(&thread_sem);

    return NULL;
}

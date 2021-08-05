#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

/**
 * database organization:
 *      (u): "user" table
 *          username    varchar(64) charset utf8 not null primary key
 *          password    varchar(124) charset utf8 not null
 *      (f): "x_friend" table
 *          username    varchar(64) charset utf8 not null primary key
 *          state       tinyint not null
 *      (m): "x_y_message" table
 *          id          bigint not null auto_increment primary key
 *          state       tinyint not null
 *          time        double not null
 *          username    varchar(64) charset utf8 not null
 *          message     varchar(804) charset utf8
 */

#define SERVER_IP                   "xxx"
#define SERVER_PORT                 25566
#define SERVER_MAX_CLIENT_NUM       10
#define SERVER_CHAT_SYN_INTERVAL    0.1

#define CLIENT_CHATFILE             "chatting"

#define LOG_USE_STDOUT
#ifndef LOG_USE_STDOUT
#define LOG_FILENAME                "/var/log/echat.log"
#endif /* LOG_USE_STDOUT */

#define DATABASE_CONNECT_HOST       "localhost"
#define DATABASE_CONNECT_USER       "xxx"
#define DATABASE_CONNECT_PASSWORD   "xxx"
#define DATABASE_CONNECT_DBNAME     "xxx"

#define TABLE_F_STATE_SEND          0x01
#define TABLE_F_STATE_RECV          0x02
#define TABLE_F_STATE_BEING         0x04
#define TABLE_M_STATE_READ          0x00
#define TABLE_M_STATE_UNREAD        0x01

#define PROTO_BUILD_KEY_P           0x00    /* flag + 512B dh_p */
#define PROTO_BUILD_KEY_PUBK        0x01    /* flag + 512B dh_pubk */

#define PROTO_SIGN_IN               0x10    /* flag + 64B username + 124B password */
#define PROTO_SIGN_UP               0x11    /* flag + 64B username + 124B password */

#define PROTO_CHAT                  0x20    /* flag */
#define PROTO_CHAT_OPTION_SEL       0x21    /* flag + 64B username */
#define PROTO_CHAT_MESSAGE          0x22    /* flag + 8B time + 804B message */

#define PROTO_SPAN                  0x30    /* flag */
#define PROTO_SPAN_OPTION_ADD       0x31    /* flag + 64B username */
#define PROTO_SPAN_OPTION_ACC       0x32    /* flag + 64B username */
#define PROTO_SPAN_OPTION_REJ       0x33    /* flag + 64B username */

#define PROTO_F_LIST                0x40    /* flag + 64B username + 1B state */
#define PROTO_F_LIST_END            0x41    /* flag */
#define PROTO_M_LIST                0x42    /* flag + 1B state + 8B time + 64B username + 804B message */
#define PROTO_M_LIST_END            0x43    /* flag */

#define PROTO_ERROR_EXIST           0x50    /* flag */
#define PROTO_ERROR_NOTEXIST        0x51    /* flag */
#define PROTO_ERROR_INCORRECT       0x52    /* flag */
#define PROTO_ERROR_UNKNOWN         0x53    /* flag */
#define PROTO_CONTINUE              0x54    /* flag */
#define PROTO_OK                    0x55    /* flag */
#define PROTO_FINISH                0x56    /* flag */
#define PROTO_DISCONNECT            0x57    /* flag */

#endif

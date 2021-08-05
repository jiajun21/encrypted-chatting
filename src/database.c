#include "protocol.h"
#include "database.h"
#include <mysql/mysql.h>
#include <stdio.h>

int database_table_exist(MYSQL * mysql, const char * table)
{
    MYSQL_RES * result;
    int ret;

    result = mysql_list_tables(mysql, table);
    if (result == NULL)
        ret = -2;
    else
    {
        if (0 == mysql_num_rows(result))
            ret = -1;
        else
            ret = 0;
        mysql_free_result(result);
    }

    return ret;
}

int database_create_table(MYSQL * mysql, const char * table,
                                    const char * definition)
{
    char command[1024];
    int ret;

    snprintf(command, 1024, "create table %s (%s)", table, definition);
    ret = database_execute(mysql, command);

    return ret;
}

int database_select(MYSQL * mysql, const char * table,
                                    const char * field,
                                    const char * constraint)
{
    char command[1024];
    int ret;

    snprintf(command, 1024, "select %s from %s %s", field, table, constraint);
    ret = database_execute(mysql, command);

    return ret;
}

int database_insert(MYSQL * mysql, const char * table,
                                    const char * field,
                                    const char * value)
{
    char command[1024];
    int ret;

    snprintf(command, 1024, "insert into %s (%s) values (%s)", table, field, value);
    ret = database_execute(mysql, command);

    return ret;
}

int database_delete(MYSQL * mysql, const char * table,
                                    const char * constraint)
{
    char command[1024];
    int ret;

    snprintf(command, 1024, "delete from %s %s", table, constraint);
    ret = database_execute(mysql, command);

    return ret;
}

int database_update(MYSQL * mysql, const char * table,
                                    const char * todo,
                                    const char * constraint)
{
    char command[1024];
    int ret;

    snprintf(command, 1024, "update %s set %s %s", table, todo, constraint);
    ret = database_execute(mysql, command);

    return ret;
}

int database_thread_init(void)
{
    return mysql_thread_init();
}

void database_thread_finish(void)
{
    mysql_thread_end();
}

int database_init(void)
{
    return mysql_library_init(0, NULL, NULL);
}

MYSQL * database_connect(void)
{
    MYSQL * mysql;

    mysql = mysql_init(NULL);
    if (mysql != NULL)
    {
        if (NULL == mysql_real_connect(mysql,
                                        DATABASE_CONNECT_HOST,
                                        DATABASE_CONNECT_USER,
                                        DATABASE_CONNECT_PASSWORD,
                                        DATABASE_CONNECT_DBNAME,
                                        0, NULL, 0))
        {
            mysql_close(mysql);
            mysql = NULL;
        }
    }

    return mysql;
}

int database_execute(MYSQL * mysql, const char * command)
{
    return mysql_query(mysql, command);
}

MYSQL_RES * database_get_result(MYSQL * mysql)
{
    return mysql_store_result(mysql);
}

uint64_t database_get_row_num(MYSQL_RES * result)
{
    return mysql_num_rows(result);
}

MYSQL_ROW database_get_row(MYSQL_RES * result)
{
    return mysql_fetch_row(result);
}

void database_free_result(MYSQL_RES * result)
{
    mysql_free_result(result);
}

void database_disconnect(MYSQL * mysql)
{
    mysql_close(mysql);
}

void database_finish(void)
{
    mysql_library_end();
}

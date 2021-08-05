#ifndef _DATABASE_H_
#define _DATABASE_H_

#include <mysql/mysql.h>

int database_table_exist(MYSQL * mysql, const char * table);

/* create table "table" ("definition") */
int database_create_table(MYSQL * mysql, const char * table,
                                    const char * definition);
/* select "field" from "table" "constraint" */
int database_select(MYSQL * mysql, const char * table,
                                    const char * field,
                                    const char * constraint);
/* insert into "table" ("field") values ("value") */
int database_insert(MYSQL * mysql, const char * table,
                                    const char * field,
                                    const char * value);
/* delete from "table" "constraint" */
int database_delete(MYSQL * mysql, const char * table,
                                    const char * constraint);
/* update "table" set "todo" "constraint" */
int database_update(MYSQL * mysql, const char * table,
                                    const char * todo,
                                    const char * constraint);

int database_thread_init(void);
void database_thread_finish(void);

int database_init(void);
MYSQL * database_connect(void);
int database_execute(MYSQL * mysql, const char * command);
MYSQL_RES * database_get_result(MYSQL * mysql);
uint64_t database_get_row_num(MYSQL_RES * result);
MYSQL_ROW database_get_row(MYSQL_RES * result);
void database_free_result(MYSQL_RES * result);
void database_disconnect(MYSQL * mysql);
void database_finish(void);

#endif

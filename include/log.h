#ifndef _LOG_H_
#define _LOG_H_

#define LOG_INFO        0x00
#define LOG_WARNING     0x01
#define LOG_ERROR       0x02

int log_init(void);
void log_print(int type, const char msg[], ...);
void log_finish(void);

#endif

#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

void logging_init(const char *name, int log_level);
void logging_cleanup();
void logging_set_log_level(int log_level);

#define log_error(...) syslog(LOG_ERR, __VA_ARGS__)
#define log_warning(...) syslog(LOG_WARNING, __VA_ARGS__)
#define log_info(...) syslog(LOG_INFO, __VA_ARGS__)
#define log_notice(...) syslog(LOG_NOTICE, __VA_ARGS__)
#define log_debug(...) syslog(LOG_DEBUG, __VA_ARGS__)

#endif
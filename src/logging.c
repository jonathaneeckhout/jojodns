#include "logging.h"

void logging_init(const char *name, int log_level)
{
    setlogmask(LOG_UPTO(log_level));

    openlog(name, LOG_PERROR | LOG_PID | LOG_NDELAY, LOG_USER);
}

void logging_cleanup()
{
    closelog();
}
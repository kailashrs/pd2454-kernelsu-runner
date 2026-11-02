/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSU_MODULE_STATE_H
#define KSU_MODULE_STATE_H
#include <stdio.h>
#include <string.h>
/* The caller owns this NUL-terminated scratch buffer. A listed module can
 * still be Loading; only Live means its initializer has succeeded. */
static inline int ksu_module_buffer_live(char *buffer)
{
    char *line = strncmp(buffer,"kernelsu ",9)==0 ? buffer : strstr(buffer,"\nkernelsu ");
    char state[16];
    if (!line) return 0;
    if (*line=='\n') line++;
    char *end=strchr(line,'\n');
    if (end) *end=0;
    return sscanf(line,"%*s %*s %*s %*s %15s",state)==1 && strcmp(state,"Live")==0;
}
#endif

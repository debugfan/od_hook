#ifndef READ_CONFIG_H
#define READ_CONFIG_H

extern int g_fix_hardware_breakpoints_bugs;
extern int g_skip_some_exceptions;
extern int g_disable_set_fore_ground_window;

void init_and_read_config(void *module);

#endif

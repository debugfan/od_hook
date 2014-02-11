#include "read_config.h"
#include <Windows.h>
#include <string>
#include "debug_log.h"

int g_fix_hardware_breakpoints_bugs = 1;
int g_skip_some_exceptions = 1;
int g_disable_set_fore_ground_window = 0;

char g_config_path[MAX_PATH] = {'\0'};

std::string extract_filepath(const std::string& s)
{
    std::string::size_type pos = 0;
    if((pos = s.find_last_of(":\\/")) != std::string::npos)
    {
        return s.substr(0, pos+1);
    }
    return s;
}

BOOL file_exists (const char *filename) 
{
    FILE *fp;
    if(fp = fopen(filename, "r"))
    {
        fclose(fp);
        return TRUE;
    } 
    else 
    {
        return FALSE;
    }   
}

void read_config()
{
    g_fix_hardware_breakpoints_bugs = GetPrivateProfileInt(
        "general",
        "fix_hardware_breakpoints_bugs",
        1,
        g_config_path);

    g_skip_some_exceptions = GetPrivateProfileInt(
        "general",
        "skip_some_exceptions",
        1,
        g_config_path);

    g_disable_set_fore_ground_window = GetPrivateProfileInt(
        "general",
        "disable_set_fore_ground_window",
        0,
        g_config_path);
}

void write_config()
{
    char temp_string[10];

    itoa(g_fix_hardware_breakpoints_bugs, temp_string, sizeof(temp_string));
    log_debug(("g_fix_hardware_breakpoints_bugs: %s", temp_string));
    WritePrivateProfileString(
        "general",
        "fix_hardware_breakpoints_bugs",
        temp_string,
        g_config_path);

    itoa(g_skip_some_exceptions, temp_string, sizeof(temp_string));
    log_debug(("g_skip_some_exceptions: %s", temp_string));
    WritePrivateProfileString(
        "general",
        "skip_some_exceptions",
        temp_string,
        g_config_path);

    itoa(g_disable_set_fore_ground_window, temp_string, sizeof(temp_string));
    log_debug(("g_disable_set_fore_ground_window: %s", temp_string));
    WritePrivateProfileString(
        "general",
        "disable_set_fore_ground_window",
        temp_string,
        g_config_path);
}

void init_and_read_config(void *module)
{
    char temp_path[MAX_PATH];
    GetModuleFileName((HMODULE)module, temp_path, sizeof(temp_path));
    strcpy(g_config_path, extract_filepath(temp_path).c_str());
    strcat(g_config_path, "hook_config.ini");
    log_info(("config path: %s", g_config_path));
    if(file_exists(g_config_path))
    {
        read_config();
    }
    else
    {
        write_config();
    }
}

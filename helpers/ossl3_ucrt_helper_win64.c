// Win64 helper: provides UCRT static local variables
// that MSVC inline functions reference

#include <stdint.h>

// Static local for __local_stdio_printf_options
uint64_t _OptionsStorage_printf = 0;

// Provide the mangled names as aliases
#pragma comment(linker, "/alternatename:?_OptionsStorage@?1??__local_stdio_printf_options@@9@9=_OptionsStorage_printf")
#pragma comment(linker, "/alternatename:?_OptionsStorage@?1??__local_stdio_scanf_options@@9@9=_OptionsStorage_printf")
#pragma comment(linker, "/alternatename:?buff@?1??gai_strerrorA@@9@9=_gai_strerror_buf")

char _gai_strerror_buf[1024] = {0};

// Also provide bio_lookup_lock and bio_type_count
void* bio_lookup_lock = 0;
int bio_type_count = 23;

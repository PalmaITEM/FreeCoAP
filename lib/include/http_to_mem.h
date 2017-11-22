
//Copyright David Palma

#include <string.h>
#include <curl/curl.h>

typedef struct MemoryStruct {
  char *memory;
  size_t size;
}
MemoryStruct;

//static size_t
//WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);

char* get_http_mem();

long http_to_mem(char *url);

void http_to_mem_cleanup();

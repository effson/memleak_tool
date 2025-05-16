#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/stat.h>

#if 0
int leak_check = 0;

void *nmalloc(size_t size, const char *file, int line) {
    void *ptr = malloc(size);
    
    if(leak_check){
        char buf[128] = {0};
        snprintf(buf, 128, "./mem/%p.mem", ptr);

        FILE *fp = fopen(buf, "w");
        if(!fp) {
            free(ptr);
            return NULL;
        }

        fprintf(fp, "[+]%s:%d addr: %p, size: %ld\n", file, line, ptr, size);
        fflush(fp);
        fclose(fp);
    }
    return ptr;
}

void nfree(void *ptr) {

    if(leak_check){
        char buf[128] = {0};
        snprintf(buf, 128, "./mem/%p.mem", ptr);

        if(unlink(buf) < 0) {
            printf("double free: %p\n", ptr);
            return;
        }
    }
    return free(ptr);
}

#define free(ptr) nfree(ptr)
#define malloc(size) nmalloc(size, __FILE__, __LINE__)

#endif

//hook
typedef void *(*malloc_t)(size_t size);
malloc_t malloc_f = NULL;

typedef void (*free_t)(void *ptr);
free_t free_f = NULL;

int enable_malloc = 1;
int enable_free = 1;
//int debug = 1;


void * ConvertToELF(void *addr) {
    Dl_info dinfo;
    struct link_map *lmap;
    dladdr1(addr, &dinfo, (void **)&lmap, RTLD_DL_LINKMAP);
    return (void *)((size_t)addr - lmap->l_addr);
}

void *malloc(size_t size) {
    void *ptr = NULL;
    
    if (enable_malloc) {
        enable_malloc = 0;
        ptr = malloc_f(size);

        void *caller = __builtin_return_address(0);

        char buf[128] = {0};
        snprintf(buf, 128, "./mem/%p.mem", ptr);

        FILE *fp = fopen(buf, "w");
        if(!fp) {
            free(ptr);
            return NULL;
        	}
		//printf("%p if malloc,%d\n", ptr, debug);
		//debug ++;
        fprintf(fp, "[+]%p, addr: %p, size: %ld\n", ConvertToELF(caller), ptr, size);
        fflush(fp);
        fclose(fp);
        enable_malloc = 1;
    } else {
		
        ptr = malloc_f(size);
		//printf("%p else malloc,%d\n", ptr, debug);
		//debug ++;
    	}

    return ptr;
}

void free(void *ptr) {
	if (ptr == NULL) return;
  if (enable_free) {
        enable_free = 0;
	      free_f(ptr);
		//printf("%p if free, %d\n", ptr, debug);
		//debug ++;
        char buf[128] = {0};
        snprintf(buf, 128, "./mem/%p.mem", ptr);

        //if(unlink(buf) < 0) {			
         //   printf("double free: %p \n", ptr); 
        	//}
        unlink(buf);
        enable_free = 1;
    } else{
		//printf("%p else free, %d\n", ptr, debug);
		//debug ++;
        free_f(ptr);
    	}
    return;
}

void init_hook() {
	mkdir("./mem", 0755);
    if(!malloc_f) {
        malloc_f = (malloc_t)dlsym(RTLD_NEXT, "malloc");
    }
    if(!free_f) {
        free_f = (free_t)dlsym(RTLD_NEXT, "free");
    }
}

int main(){

    init_hook();
    void *ptr1 = malloc(5);
	printf("%p  1\n",ptr1);
    void *ptr2 = malloc(10);
	printf("%p  2\n",ptr2);	
    void *ptr3 = malloc(15);
	printf("%p  3\n",ptr3);
	
    free(ptr1);	
    free(ptr3);

    return 0;
}

/* memory.h
 *
 */


#ifndef __WCC_MEMORY_H__
#define __WCC_MEMORY_H__

#include <stdlib.h>
#include <wccTypes.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef void *(*wolfSSL_Malloc_cb)(size_t size);
typedef void (*wolfSSL_Free_cb)(void *ptr);
typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size);


/* Public set function */
WOLFSSL_API int wolfSSL_SetAllocators(wolfSSL_Malloc_cb  malloc_function, wolfSSL_Free_cb    free_function, wolfSSL_Realloc_cb realloc_function);

/* Public in case user app wants to use XMALLOC/XFREE */
WOLFSSL_API void* wolfSSL_Malloc(size_t size);
WOLFSSL_API void  wolfSSL_Free(void *ptr);
WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size);


#ifdef __cplusplus
	}
#endif

#endif


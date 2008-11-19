#ifndef TRIPCRUNCH_H_INCLUDE
#define TRIPCRUNCH_H_INCLUDE

// Required for pthread.
#define _MULTI_THREADED

#include <pthread.h>

/** Used to lock critical sections in hash calculations if necessary. */
extern pthread_mutex_t hash_mutex;

#endif

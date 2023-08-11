#include <features.h>
#include <stdlib.h>
#if !defined(__GLIBC__) && (defined(__ARM_ARCH_7__) || defined(__i386__))

__attribute__((weak))
int __nanosleep64(void *req, void *rem) {
	(void) req;
	(void) rem;
	abort();
}
__attribute__((weak))
int __nanosleep_time64(void *req, void *rem) {
    return __nanosleep64(req, rem);
}

__attribute__((weak))
int __pthread_cond_timedwait64(void *cond, void *mutex, void *abstime) {
	(void) cond;
	(void) mutex;
	(void) abstime;
	abort();
}
__attribute__((weak))
int __pthread_cond_timedwait_time64(void *cond, void *mutex, void *abstime) {
    return __pthread_cond_timedwait64(cond, mutex, abstime);
}

__attribute__((weak))
void *dlsym(void * handle, const char *name) {
	(void) handle;
	(void) name;
	abort();
}
__attribute__((weak))
void *__dlsym_time64(void *handle, const char *name) {
    return dlsym(handle, name);
}
#endif

#ifndef RUST_C_LIB_H
#define RUST_C_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

bool check_string(const char *c_string);

#ifdef __cplusplus
}
#endif

#endif // RUST_C_LIB_H


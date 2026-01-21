#ifndef TINYHOOK_H
#define TINYHOOK_H

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hooks a function in the target process.
 *
 * @param task The task port of the target process.
 * @param src The address of the function to hook.
 * @param dst The address of the replacement function.
 * @param orig A pointer to store the address of the original function.
 * @return 0 on success, or a non-zero error code on failure.
 */
int tiny_hook(task_t task, void *src, void *dst, void **orig);

#ifdef __cplusplus
}
#endif

#endif // TINYHOOK_H
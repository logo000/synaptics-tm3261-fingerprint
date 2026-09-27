/* Minimal libfprint error/logging shim for hardware-independent helper tests.
 * Production sources are included unchanged; USB uses the real libgusb. */
#pragma once
#include <gio/gio.h>
#include <gusb.h>
#include <stdarg.h>
#define FP_DEVICE_ERROR (g_quark_from_static_string("test-fp-error"))
enum { FP_DEVICE_ERROR_GENERAL, FP_DEVICE_ERROR_PROTO, FP_DEVICE_ERROR_DATA_INVALID };
#define fp_dbg(...) g_debug(__VA_ARGS__)
#define fp_info(...) g_info(__VA_ARGS__)
#define fp_warn(...) g_warning(__VA_ARGS__)
static inline GError *fpi_device_error_new_msg(int code, const char *fmt, ...) {
  va_list ap; va_start(ap,fmt);
  GError *error=g_error_new_valist(FP_DEVICE_ERROR,code,fmt,ap);
  va_end(ap); return error;
}

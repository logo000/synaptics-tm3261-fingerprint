"""Exercise the production completion callback with floating GObject prints."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

src = (Path(__file__).resolve().parents[1] / 'src/s00a8.c').read_text()
callback = src[src.index('static void\nverify_done_cb'):src.index('static void\ndev_verify')]
pre = r'''
#include <glib-object.h>
typedef GObject FpPrint;
typedef GObject FpDevice;
typedef void FpiSsm;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(FpPrint, g_object_unref)
typedef struct { void *task_ssm; FpPrint *identify_match; char template[1]; int verify_result; } State;
typedef State FpiDeviceSynaptics00a8;
static State state;
#define FPI_DEVICE_SYNAPTICS00A8(d) (&state)
#define FPI_DEVICE_ACTION_IDENTIFY 1
#define FP_DEVICE_RETRY 2
#define FP_DEVICE_ERROR_DATA_INVALID 3
#define FPI_MATCH_ERROR 4
static gboolean destroyed, fail_scan;
static FpPrint *reported;
static guint reports, completes;
static void gone(gpointer data, GObject *obj) { destroyed = TRUE; }
static int fpi_device_get_current_action(FpDevice *d) { return 1; }
static FpPrint *make_scanned_print(FpDevice *d, const char *tpl) {
 if(fail_scan) return NULL;
 GObject *p = g_object_new(G_TYPE_INITIALLY_UNOWNED, NULL);
 g_object_weak_ref(p, gone, NULL); return p;
}
static GError *fpi_device_error_new_msg(int code, const char *msg) {
 return g_error_new_literal(5, code, msg);
}
static void fpi_device_identify_report(FpDevice *d, FpPrint *match, FpPrint *print, GError *err) {
 reports++; if(print) reported=g_object_ref_sink(print); g_clear_error(&err);
}
static void fpi_device_identify_complete(FpDevice *d, GError *err) {
 completes++; if(reported) g_assert_false(destroyed); g_clear_error(&err);
}
static void fpi_device_verify_report(FpDevice *d, int result, FpPrint *p, GError *e) { g_assert_not_reached(); }
static void fpi_device_verify_complete(FpDevice *d, GError *e) { g_assert_not_reached(); }
'''
main = r'''
int main(void) {
 for(int matched=0; matched<2; matched++) {
   destroyed=FALSE; reports=completes=0;
   state.identify_match=matched ? g_object_new(G_TYPE_OBJECT,NULL) : NULL;
   GObject *gallery=state.identify_match;
   verify_done_cb(NULL,NULL,NULL);
   g_assert_cmpuint(reports,==,1); g_assert_cmpuint(completes,==,1);
   g_assert_null(state.identify_match); g_assert_false(destroyed);
   g_clear_object(&reported); g_assert_true(destroyed); g_clear_object(&gallery);
 }
 for(int kind=0; kind<3; kind++) {
   reports=completes=0; fail_scan=kind==2;
   GError *e=kind==2 ? NULL : g_error_new_literal(kind==0 ? FP_DEVICE_RETRY : 5,1,"test");
   verify_done_cb(NULL,NULL,e);
   g_assert_cmpuint(reports,==,kind==0 ? 1 : 0);
   g_assert_cmpuint(completes,==,1); g_assert_null(reported);
 }
 g_print("PASS: identify print ownership, match/no-match, retry, error and scan failure\n");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.c').write_text(pre + callback + main)
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gobject-2.0'], text=True))
    subprocess.run([os.environ.get('CC', 'clang'), '-g', '-O1', '-Wall', '-Werror', '-fsanitize=address,undefined', str(p/'test.c'), '-o', str(p/'test'), *flags], check=True)
    subprocess.run([str(p/'test')], check=True)

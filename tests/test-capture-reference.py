from pathlib import Path
import os, subprocess, tempfile
src=(Path(__file__).resolve().parents[1]/'src/s00a8.c').read_text()
helpers=src[src.index('static gboolean\nload_capture_reference'):src.index('static void capture_send')]
pre=r'''
#include <glib.h>
#include <glib/gstdio.h>
#include <math.h>
#include <string.h>
#include <sys/stat.h>
#define S00A8_PIXELS (144*56)
#define fp_info(...) ((void)0)
#define fp_warn(...) g_warning(__VA_ARGS__)
typedef void GUsbDevice;
typedef struct {guint8 *cal_frame; gfloat *baseline; gboolean have_cal, have_baseline;} FpiDeviceSynaptics00a8;
static gchar *testpath;
static gchar *baseline_path(GUsbDevice *usb) {return g_strdup(testpath);}
static gchar *s00a8_file_read_bounded(const gchar *p,gsize max,gsize *n,GError **err) {
 gchar *data=NULL; if(!g_file_get_contents(p,&data,n,err))return NULL;
 if(*n>max){g_free(data);return NULL;} return data;
}
'''
main=r'''
int main(int argc,char **argv) {
 testpath=argv[1];
 guint8 raw[S00A8_PIXELS], loaded_raw[S00A8_PIXELS];
 gfloat corrected[S00A8_PIXELS], loaded_corrected[S00A8_PIXELS];
 for(guint i=0;i<S00A8_PIXELS;i++){raw[i]=i%251;corrected[i]=128.25f+(i%7);}
 FpiDeviceSynaptics00a8 a={raw,corrected,FALSE,FALSE}, b={loaded_raw,loaded_corrected,FALSE,FALSE};
 g_assert_false(load_capture_reference(&b,NULL));
 umask(0);
 save_capture_reference(&a,NULL);
 struct stat st; g_assert_cmpint(stat(testpath,&st),==,0);
 g_assert_cmpint(st.st_mode & 0777,==,0600);
 g_assert_true(load_capture_reference(&b,NULL));
 g_assert_true(b.have_cal && b.have_baseline);
 g_assert_cmpmem(raw,sizeof raw,loaded_raw,sizeof loaded_raw);
 g_assert_cmpmem(corrected,sizeof corrected,loaded_corrected,sizeof loaded_corrected);
 g_file_set_contents(testpath,(char*)corrected,sizeof corrected,NULL);
 b.have_cal=b.have_baseline=FALSE;
 g_assert_false(load_capture_reference(&b,NULL));
 for(guint j=0;j<3;j++) {
   corrected[5]=j==0?NAN:j==1?-1.0f:256.0f;
   save_capture_reference(&a,NULL);
   g_assert_false(load_capture_reference(&b,NULL));
   g_assert_false(b.have_cal || b.have_baseline);
 }
 g_unlink(testpath);
 g_print("PASS: distinct calibration/baseline round trip; missing, legacy, NaN and out-of-range references rejected\n");
 return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d); (p/'test.c').write_text(pre+helpers+main)
 flags=subprocess.check_output(['pkg-config','--cflags','--libs','glib-2.0'],text=True).split()
 sanitize = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if os.environ.get('SANITIZE', '1') == '1' else []
 subprocess.run([os.environ.get('CC', 'clang'),'-g','-O1','-Wall','-Werror',*sanitize,str(p/'test.c'),'-o',str(p/'test'),*flags,'-lm'],check=True)
 subprocess.run([str(p/'test'),str(p/'cache')],check=True)

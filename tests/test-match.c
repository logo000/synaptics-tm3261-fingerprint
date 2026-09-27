#include "../src/s00a8-match.c"
int main(void) {
 gint8 tpl[N];gfloat px[N]={0};gdouble poses[7]={0,1,0,0,1,72,112};
 g_assert_cmpfloat(s00a8_match_prepare(px,tpl),==,0);
 g_assert_null(s00a8_model_new(tpl,1,poses));
 g_autoptr(S00a8Aligner) a=s00a8_aligner_new();
 s00a8_aligner_add(a,tpl);
 g_assert_null(s00a8_aligner_finish(a,NULL));
 g_assert_null(s00a8_model_new(tpl,0,poses));
 for(guint i=0;i<N;i++) tpl[i]=(i*37%251)-125;
 for(guint k=0;k<7;k++) {
  gdouble copy[7];memcpy(copy,poses,sizeof poses);copy[k]=NAN;
  g_assert_null(s00a8_model_new(tpl,1,copy));
  copy[k]=G_MAXDOUBLE;g_assert_null(s00a8_model_new(tpl,1,copy));
 }
 gdouble invalid[7]={0,0,0,0,0,72,112};
 g_assert_null(s00a8_model_new(tpl,1,invalid));
 g_autoptr(S00a8Model) md=s00a8_model_new(tpl,1,poses);
 g_assert_nonnull(md);g_assert_cmpfloat(s00a8_model_score(md,tpl),>,0.99);
 memset(tpl,-128,sizeof tpl);g_assert_cmpfloat(s00a8_model_score(md,tpl),<,0);
 g_print("Matcher: empty enrolment, invalid poses, self match and blank rejection passed\n");
}

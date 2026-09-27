#include "../src/s00a8-tls.c"
/* Hardware transport is not called by these record/parser tests. */
gboolean s00a8_usb_exchange(GUsbDevice *u, GCancellable *c, const guint8 *o,
 gsize ol, guint8 *i, gsize il, gsize *n, GError **e) { g_assert_not_reached(); }
static void init(S00a8Tls *t) {
 memset(t,0,sizeof *t); t->active=TRUE;
 t->transcript=EVP_MD_CTX_new();
 g_assert_cmpint(EVP_DigestInit_ex(t->transcript,EVP_sha256(),NULL),==,1);
}
static gboolean flight(S00a8Tls *t, int mode) {
 g_autoptr(GByteArray) hs=g_byte_array_new(), rec=g_byte_array_new();
 guint8 hello[38]={3,3}; hello[35]=0xc0;hello[36]=5;
 if(mode==4) hello[37]=1;
 if(mode==3) append_hs(hs,HS_SERVER_HELLO_DONE,NULL,0);
 append_hs(hs,HS_SERVER_HELLO,hello,sizeof hello);
 if(mode==1) append_hs(hs,HS_SERVER_HELLO,hello,sizeof hello);
 append_hs(hs,HS_CERTIFICATE_REQUEST,NULL,0);
 if(mode==2) append_hs(hs,HS_CERTIFICATE_REQUEST,NULL,0);
 append_hs(hs,HS_SERVER_HELLO_DONE,NULL,0);
 if(mode==5) append_hs(hs,HS_SERVER_HELLO_DONE,NULL,0);
 append_record(rec,CT_HANDSHAKE,hs->data,hs->len);
 return parse_server_flight(t,rec->data,rec->len,NULL);
}
int main(void) {
 S00a8Tls t; init(&t); guint8 data[256]; gsize n=0,m=0;
 for(guint i=0;i<sizeof data;i++) data[i]=i;
 for(guint len=0;len<sizeof data;len++) {
  g_autofree guint8 *r=s00a8_tls_wrap(&t,data,len,&n,NULL);
  g_assert_nonnull(r);
  g_autofree guint8 *p=s00a8_tls_unwrap(&t,r,n,&m,NULL);
  g_assert_nonnull(p); g_assert_cmpuint(m,==,len); g_assert_cmpmem(p,m,data,len);
  r[n-1]^=1; g_assert_null(s00a8_tls_unwrap(&t,r,n,&m,NULL));
 }
 g_assert_null(s00a8_tls_wrap(&t,data,G_MAXSIZE,&n,NULL));
 g_assert_null(s00a8_tls_wrap(&t,data,65535,&n,NULL));
 guint8 bad[80]={0x17,3,3};
 for(guint len=0;len<sizeof bad;len++) {
  if(len>=5) put_be16(bad+3,len-5);
  g_assert_null(s00a8_tls_unwrap(&t,bad,len,&m,NULL));
  g_assert_false(check_server_finished(&t,bad,len,NULL));
 }
 for(int mode=0;mode<6;mode++) {
  s00a8_tls_clear(&t); init(&t);
  g_assert_cmpint(flight(&t,mode),==,mode==0);
 }
 /* A valid record MAC must not substitute for the handshake transcript check. */
 guint8 digest[32], finished[HS_HEADER+VERIFY_DATA_LEN]={HS_FINISHED};
 put_be24(finished+1,VERIFY_DATA_LEN);
 g_assert_true(transcript_hash(&t,digest));
 g_assert_true(prf(t.master_secret,sizeof t.master_secret,"server finished",
                   digest,sizeof digest,finished+HS_HEADER,VERIFY_DATA_LEN));
 for(guint wrong=0;wrong<2;wrong++) {
  g_autoptr(GByteArray) server=g_byte_array_new();
  const guint8 ccs=1;
  if(wrong) finished[HS_HEADER]^=1;
  g_autofree guint8 *r=encrypt_record(&t,CT_HANDSHAKE,finished,sizeof finished,&n);
  append_record(server,CT_CHANGE_CIPHER_SPEC,&ccs,1);
  g_byte_array_append(server,r,n);
  g_assert_cmpint(check_server_finished(&t,server->data,server->len,NULL),==,!wrong);
  for(guint cut=0;cut<server->len;cut++)
   g_assert_false(check_server_finished(&t,server->data,cut,NULL));
 }
 GRand *rng=g_rand_new_with_seed(42);
 for(guint i=0;i<2000;i++) {
  guint len=g_rand_int_range(rng,0,sizeof data);
  for(guint k=0;k<len;k++) data[k]=g_rand_int(rng);
  g_autofree guint8 *p=s00a8_tls_unwrap(&t,data,len,&m,NULL);
  g_assert_null(p);
  g_assert_false(parse_server_flight(&t,data,len,NULL));
  g_assert_false(check_server_finished(&t,data,len,NULL));
 }
 g_rand_free(rng); s00a8_tls_clear(&t);
 g_print("TLS: round trips, tampering, oversized lengths, malformed flights and 2000 random inputs passed\n");
}

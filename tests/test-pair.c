#include "../src/s00a8-pair.c"
int main(void) {
 g_autofree gchar *dir=g_dir_make_tmp("s00a8-tests-XXXXXX",NULL);
 g_autofree gchar *file=g_build_filename(dir,"bounded",NULL);
 gsize len;g_assert_true(g_file_set_contents(file,"abc",3,NULL));
 g_autofree gchar *data=s00a8_file_read_bounded(file,3,&len,NULL);
 g_assert_cmpuint(len,==,3);g_assert_cmpmem(data,len,"abc",3);
 g_assert_null(s00a8_file_read_bounded(file,2,&len,NULL));
 g_assert_null(s00a8_file_read_bounded(file,G_MAXSIZE,&len,NULL));
 guint8 invalid[64]={0};g_assert_false(sensor_public_key_valid(invalid));
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_name(NULL,"EC",NULL);EVP_PKEY *key=NULL;
 g_assert_cmpint(EVP_PKEY_keygen_init(ctx),==,1);
 g_assert_cmpint(EVP_PKEY_CTX_set_group_name(ctx,"prime256v1"),==,1);
 g_assert_cmpint(EVP_PKEY_keygen(ctx,&key),==,1);
 guint8 point[65],cert[S00A8_CERT_LEN];
 g_assert_cmpint(EVP_PKEY_get_octet_string_param(key,OSSL_PKEY_PARAM_PUB_KEY,point,sizeof point,&len),==,1);
 g_assert_true(sensor_public_key_valid(point+1));cert_set_key(cert,point+1);
 g_assert_true(key_matches_cert(key,cert));cert[8]^=1;g_assert_false(key_matches_cert(key,cert));
 EVP_PKEY_free(key);EVP_PKEY_CTX_free(ctx);g_unlink(file);g_rmdir(dir);
 g_print("Pairing: bounded reads, invalid EC point and certificate/key mismatch passed\n");
}

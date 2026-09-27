#include "../src/s00a8-image.c"
#include "../src/s00a8-program.c"
int main(void) {
 guint op;guint32 reg; g_assert_cmpuint(ts_insn(NULL,0,&op,&reg),==,0);
 guint8 cal[S00A8_FACTORY_CAL_LEN], blank[S00A8_PIXELS];
 memset(blank,128,sizeof blank);
 for(guint variant=0;variant<3;variant++) {
  for(guint i=0;i<sizeof cal;i++) cal[i]=variant==0?128:variant==1?i:(i%2?255:0);
  guint8 bits,base;gsize packed_len;
  g_autofree guint8 *packed=pack_samples(cal,sizeof cal,&bits,&base,&packed_len);
  g_assert_cmpuint(bits,>=,1);g_assert_cmpuint(bits,<=,8);
  for(guint i=0;i<sizeof cal;i++) {
   guint value=0;
   for(guint b=0;b<bits;b++) value|=((packed[(i*bits+b)/8]>>((i*bits+b)%8))&1)<<b;
   g_assert_cmpuint(base+value,==,cal[i]);
  }
  for(guint corrected=0;corrected<2;corrected++) {
   gsize len;g_autofree guint8 *cmd=s00a8_capture_command(225,cal,corrected?blank:NULL,&len);
   g_assert_nonnull(cmd);g_assert_cmpuint(len,>,1688);g_assert_cmpuint(len%64,!=,0);
   gsize pos=5;while(pos+4<=len) {gsize n=cmd[pos+2]|cmd[pos+3]<<8;g_assert_cmpuint(pos+4+n,<=,len);pos+=4+n;}
   g_assert_cmpuint(pos,==,len);
  }
 }
 gfloat out[S00A8_PIXELS];
 const gsize size=S00A8_LINES_PER_FRAME*S00A8_LINE_STRIDE;
 g_autofree guint8 *raw=g_malloc0(size);
 for(guint row=0;row<S00A8_LINES_PER_FRAME;row++) {
  guint8 *line=raw+row*S00A8_LINE_STRIDE;line[0]=1;line[1]=0xfe;line[2]=row;
  memset(line+8,64,S00A8_WIDTH);
 }
 g_assert_cmpuint(s00a8_image_decode(raw,size,out),==,1);
 for(guint i=0;i<S00A8_PIXELS;i++) g_assert_cmpfloat(out[i],==,64);
 for(guint len=0;len<size;len+=113) g_assert_cmpuint(s00a8_image_decode(raw,len,out),==,0);
 g_print("Image/program: frame truncations, empty instruction, packing extremes and command chunk bounds passed\n");
}

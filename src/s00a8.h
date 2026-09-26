/*
 * Synaptics 06cb:00a8 fingerprint reader - shared definitions
 *
 * Copyright (C) 2026 The libfprint-synaptics-06cb-00a8 authors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <glib.h>
#include <gusb.h>

/* ---- USB ---------------------------------------------------------------- */

#define S00A8_EP_CMD_OUT        0x01
#define S00A8_EP_CMD_IN         0x81
#define S00A8_EP_IMAGE_IN       0x82

#define S00A8_TIMEOUT_MS        5000
#define S00A8_MAX_RESPONSE      (24 * 1024)

/* ---- Sensor image ------------------------------------------------------- */

#define S00A8_WIDTH             144
#define S00A8_HEIGHT            56
#define S00A8_PIXELS            (S00A8_WIDTH * S00A8_HEIGHT)

/* Every line on EP 0x82 is an 8 byte header (01 fe <u16 counter> ...)
 * followed by 144 samples; each image row is sampled twice, so one frame
 * has 2 * 56 lines. */
#define S00A8_LINE_HEADER       8
#define S00A8_LINE_STRIDE       (S00A8_LINE_HEADER + S00A8_WIDTH)
#define S00A8_LINE_REPEAT       2
#define S00A8_LINES_PER_FRAME   (S00A8_HEIGHT * S00A8_LINE_REPEAT)

/* Per-row calibration values the sensor stores at the factory. */
#define S00A8_FACTORY_CAL_LEN   S00A8_HEIGHT

/* ---- Secure channel ----------------------------------------------------- */

/* The sensor speaks a TLS 1.2 dialect (ECDH-ECDSA, AES-256-CBC,
 * HMAC-SHA256) over the command endpoints. */
typedef struct
{
  gboolean  active;
  guint8    client_random[32];
  guint8    server_random[32];
  guint8    master_secret[48];
  guint8    client_mac_key[32];
  guint8    server_mac_key[32];
  guint8    client_key[32];
  guint8    server_key[32];
  gpointer  transcript;       /* EVP_MD_CTX *, running handshake hash */
} S00a8Tls;

/* Pairing between this host and the sensor: the host key pair, the host
 * certificate the sensor signed for it, and the sensor's ECDH key. */
#define S00A8_CERT_LEN          184

typedef struct
{
  guint8    cert[S00A8_CERT_LEN];
  gpointer  host_key;         /* EVP_PKEY *, P-256 */
  guint8    sensor_pub[64];   /* X || Y, big endian */
  gboolean  pending;          /* local commit marker remains after ambiguous pairing */
} S00a8Pairing;

/* s00a8-tls.c */
void      s00a8_tls_clear (S00a8Tls *tls);
gboolean  s00a8_tls_handshake (GUsbDevice         *usb,
                               GCancellable       *cancellable,
                               S00a8Tls           *tls,
                               const S00a8Pairing *pairing,
                               GError            **error);
gboolean  s00a8_tls_is_unpaired_error (const GError *error);
guint8   *s00a8_tls_wrap (S00a8Tls     *tls,
                          const guint8 *plain,
                          gsize         plain_len,
                          gsize        *out_len,
                          GError      **error);
guint8   *s00a8_tls_unwrap (S00a8Tls     *tls,
                            const guint8 *record,
                            gsize         record_len,
                            gsize        *out_len,
                            GError      **error);

/* s00a8-pair.c */
gchar    *s00a8_state_path (const gchar *name);
gboolean  s00a8_device_state_init (GUsbDevice *usb, GError **error);
gchar    *s00a8_device_state_path (GUsbDevice *usb, const gchar *name);
gchar    *s00a8_file_read_bounded (const gchar *path,
                                   gsize max_len,
                                   gsize *out_len,
                                   GError **error);
void      s00a8_pairing_clear (S00a8Pairing *pairing);
gboolean  s00a8_pairing_load (GUsbDevice   *usb,
                              S00a8Pairing *pairing,
                              gboolean     *state_exists,
                              GError      **error);
gboolean  s00a8_pairing_remove_saved (GUsbDevice *usb, GError **error);
gboolean  s00a8_pairing_commit_pending (GUsbDevice *usb,
                                        S00a8Pairing *pairing,
                                        GError **error);
gboolean  s00a8_pairing_create (GUsbDevice   *usb,
                                GCancellable *cancellable,
                                S00a8Pairing *pairing,
                                GError      **error);
gboolean  s00a8_usb_exchange (GUsbDevice   *usb,
                              GCancellable *cancellable,
                              const guint8 *out,
                              gsize         out_len,
                              guint8       *in,
                              gsize         in_size,
                              gsize        *in_len,
                              GError      **error);
gboolean  s00a8_plain_command (GUsbDevice   *usb,
                               GCancellable *cancellable,
                               const guint8 *cmd,
                               gsize         cmd_len,
                               GError      **error);

/* Values recovered by reverse engineering that the sensor needs to run,
 * kept in their own translation units, separate from the driver logic:
 *
 *   s00a8-program-data.c   the capture program for sensor type 0x2449
 *                          (ROM 6.20) and the receive electrode per row;
 *   s00a8-session-data.c   the 660 byte session setup payload;
 *   s00a8-config-data.c    the 10500 byte scan configuration blob.
 */
extern const guint8 validity_capture33_prog_2449_6_20[1688];
extern const guint8 validity_capture33_calib_2449[56];

#define VALIDITY_INIT_MSG4_PAYLOAD_LEN     660
extern const guint8 validity_init_msg4_payload[VALIDITY_INIT_MSG4_PAYLOAD_LEN];

#define VALIDITY_ENROLL_HOSTPART_BLOB_LEN  10500
extern const guint8 validity_enroll_hostpart_blob[VALIDITY_ENROLL_HOSTPART_BLOB_LEN];
extern const guint8 validity_enroll_hostpart_blob_clean_slate[VALIDITY_ENROLL_HOSTPART_BLOB_LEN];

/* s00a8-pair-data.c: the 5796 byte session payload used only while
 * pairing a sensor that has no pairing with this host yet. */
#define VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN 5796
extern const guint8 validity_init_msg4_clean_slate_payload[VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN];

/* s00a8-program.c */
guint8   *s00a8_capture_command (guint16       lines,
                                 const guint8 *factory_cal,
                                 const guint8 *blank,
                                 gsize        *out_len);

/* s00a8-image.c */
guint     s00a8_image_decode (const guint8 *raw,
                              gsize         raw_len,
                              gfloat       *out);
void      s00a8_image_demux (const gfloat *img,
                             const gfloat *base,
                             gfloat       *out);
gdouble   s00a8_image_difference (const gfloat *a,
                                  const gfloat *b);

/* s00a8-match.c */
#define S00A8_POSE_LEN          7

typedef struct _S00a8Model S00a8Model;
typedef struct _S00a8Aligner S00a8Aligner;

gdouble        s00a8_match_prepare (const gfloat *px,
                                    gint8        *tpl);
S00a8Aligner  *s00a8_aligner_new (void);
void           s00a8_aligner_add (S00a8Aligner *al,
                                  const gint8  *tpl);
S00a8Model    *s00a8_aligner_finish (S00a8Aligner *al,
                                     gdouble      *poses);
void           s00a8_aligner_free (S00a8Aligner *al);
S00a8Model    *s00a8_model_new (const gint8   *tpls,
                                guint          n,
                                const gdouble *poses);
guint          s00a8_model_islands (S00a8Model *md);
gdouble        s00a8_model_score (S00a8Model  *md,
                                  const gint8 *probe);
void           s00a8_model_free (S00a8Model *md);
gdouble        s00a8_match_self_score (const gint8 *probe);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (S00a8Model, s00a8_model_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (S00a8Aligner, s00a8_aligner_free)

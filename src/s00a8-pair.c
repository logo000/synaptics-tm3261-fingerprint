/*
 * Synaptics 06cb:00a8 - pairing
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

/*
 * Pairing gives the host a P-256 key the sensor trusts: the host sends a
 * certificate request with a fresh public key (command 0x4f), signed with
 * the "pairing key" every Synaptics sensor of this family accepts, and the
 * sensor returns the certificate it will require in every later TLS
 * handshake. Command 0x50 then reports the sensor's own static ECDH key.
 *
 * The pairing key is derived from a fixed, publicly documented constant
 * (see python-validity, validitysensor/tls.py). Both the host key and the
 * sensor data are stored in the state directory, readable by root only
 * when running inside fprintd.
 */

#define FP_COMPONENT "synaptics00a8"

#include "drivers_api.h"
#include "s00a8.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>

#define CMD_ROM_INFO      0x01
#define CMD_PAIR_INIT     0x19
#define CMD_ISSUE_CERT    0x4f
#define CMD_SENSOR_KEYS   0x50
#define CMD_PAIR_DONE     0x1a

#define CERT_REQ_VALUE    444
#define SENSOR_KEY_X      534
#define SENSOR_KEY_Y      602

#define FILE_CERT         "cert-blob"
#define FILE_HOST_KEY     "host-key.pem"
#define FILE_SENSOR_KEY   "device-ecdh-pubkey.bin"
#define FILE_PAIR_PENDING "pairing.pending"
#define MAX_HOST_KEY_LEN  (16 * 1024)

/* Pairing password of the Synaptics "validity" sensor family. */
static const guint8 pairing_password[32] = {
  0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
  0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
  0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38,
  0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
};

/* Resolve the identity once per GUsbDevice. A serial descriptor failure is
 * an error; switching to a different fallback during an open could split a
 * single pairing transaction across state directories. */
gboolean
s00a8_device_state_init (GUsbDevice *usb, GError **error)
{
  static const gchar state_id_key[] = "s00a8-device-state-id";
  g_autofree gchar *serial = NULL;
  g_autofree gchar *fallback = NULL;
  g_autofree gchar *id = NULL;
  const gchar *platform_id;
  guint8 serial_index;

  if (g_object_get_data (G_OBJECT (usb), state_id_key) != NULL)
    return TRUE;

  serial_index = g_usb_device_get_serial_number_index (usb);
  if (serial_index != 0)
    {
      serial = g_usb_device_get_string_descriptor (usb, serial_index, error);
      if (serial == NULL)
        {
          if (error == NULL || *error == NULL)
            g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                                 "cannot read the sensor serial number");
          return FALSE;
        }
      if (*serial == '\0')
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "sensor serial number is empty");
          return FALSE;
        }
      id = g_compute_checksum_for_string (G_CHECKSUM_SHA256, serial, -1);
    }

  if (id == NULL)
    {
      /* Devices without a serial descriptor use the stable platform id or
       * USB location. This choice is cached for this GUsbDevice instance. */
      platform_id = g_usb_device_get_platform_id (usb);
      if (platform_id != NULL && *platform_id != '\0')
        id = g_compute_checksum_for_string (G_CHECKSUM_SHA256, platform_id, -1);
      else
        {
          g_autoptr(GString) ports = g_string_new (NULL);
          GUsbDevice *node = g_object_ref (usb);

          while (node != NULL)
            {
              GUsbDevice *parent = g_usb_device_get_parent (node);

              if (ports->len > 0)
                g_string_append_c (ports, '/');
              g_string_append_printf (ports, "%u", g_usb_device_get_port_number (node));
              g_object_unref (node);
              node = parent;
            }
          fallback = g_strdup_printf ("%04x:%04x:%u:%s",
                                     g_usb_device_get_vid (usb), g_usb_device_get_pid (usb),
                                     g_usb_device_get_bus (usb), ports->str);
          id = g_compute_checksum_for_string (G_CHECKSUM_SHA256, fallback, -1);
        }
    }
  g_object_set_data_full (G_OBJECT (usb), state_id_key,
                          g_steal_pointer (&id), g_free);
  return TRUE;
}

gchar *
s00a8_device_state_path (GUsbDevice *usb, const gchar *name)
{
  static const gchar state_id_key[] = "s00a8-device-state-id";
  const gchar *id;
  g_autofree gchar *base = s00a8_state_path (".");
  g_autofree gchar *dir = NULL;

  if (!s00a8_device_state_init (usb, NULL))
    return NULL;
  id = g_object_get_data (G_OBJECT (usb), state_id_key);
  dir = g_build_filename (base, "devices", id, NULL);

  if (g_mkdir_with_parents (dir, 0700) != 0)
    fp_warn ("cannot create %s: %s", dir, g_strerror (errno));
  return g_build_filename (dir, name, NULL);
}

/* ---- storage ------------------------------------------------------------ */

/* Inside fprintd (systemd sets STATE_DIRECTORY, the home directory is
 * not accessible) state lives in /var/lib/fprint; otherwise in the
 * user's data directory. */
gchar *
s00a8_state_path (const gchar *name)
{
  const gchar *state = g_getenv ("STATE_DIRECTORY");
  g_autofree gchar *dir = NULL;

  if (state && *state)
    dir = g_build_filename (state, "synaptics-06cb-00a8", NULL);
  else
    dir = g_build_filename (g_get_user_data_dir (), "libfprint",
                            "synaptics-06cb-00a8", NULL);
  if (g_mkdir_with_parents (dir, 0700) != 0)
    fp_warn ("cannot create %s: %s", dir, g_strerror (errno));
  return g_build_filename (dir, name, NULL);
}

/* Read no more than max_len + 1 bytes, so a corrupt or hostile state file
 * cannot force an unbounded allocation before its size is rejected. */
gchar *
s00a8_file_read_bounded (const gchar *path, gsize max_len,
                         gsize *out_len, GError **error)
{
  g_autoptr(GFile) file = g_file_new_for_path (path);
  g_autoptr(GFileInputStream) stream = g_file_read (file, NULL, error);
  g_autofree gchar *data = NULL;
  gsize got = 0;

  if (stream == NULL)
    return NULL;
  if (max_len == G_MAXSIZE)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "bounded read limit is too large");
      return NULL;
    }

  data = g_malloc (max_len + 1);
  while (got < max_len + 1)
    {
      gssize n = g_input_stream_read (G_INPUT_STREAM (stream), data + got,
                                      max_len + 1 - got, NULL, error);

      if (n < 0)
        return NULL;
      if (n == 0)
        break;
      got += n;
    }
  if (got > max_len)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s exceeds the %zu byte limit", path, max_len);
      return NULL;
    }

  *out_len = got;
  return g_steal_pointer (&data);
}

/* Pairing is sensor-specific.  The platform id identifies the physical USB
 * device and is hashed so a system path never becomes part of a filename. */
static gchar *
pairing_state_path (GUsbDevice *usb, const gchar *name)
{
  return s00a8_device_state_path (usb, name);
}

/* Best-effort fsync of a path's containing directory so an unlink or a
 * marker change reaches disk. A failure here never fails the operation. */
static void
sync_dir_of (const gchar *path)
{
  g_autofree gchar *dir = g_path_get_dirname (path);
  int fd = g_open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);

  if (fd >= 0)
    {
      (void) fsync (fd);
      g_close (fd, NULL);
    }
}

static gboolean
write_private (GUsbDevice *usb, const gchar *name,
               const void *data, gsize len, GError **error)
{
  g_autofree gchar *path = pairing_state_path (usb, name);

  /* DURABLE makes GLib fsync the file and its containing directory. */
  return g_file_set_contents_full (path, data, len,
                                   G_FILE_SET_CONTENTS_CONSISTENT |
                                   G_FILE_SET_CONTENTS_DURABLE,
                                   0600, error);
}

static gboolean
read_exact (GUsbDevice *usb, const gchar *name, void *out,
            gsize len, GError **error)
{
  g_autofree gchar *path = pairing_state_path (usb, name);
  g_autofree gchar *data = NULL;
  gsize got = 0;

  data = s00a8_file_read_bounded (path, len, &got, error);
  if (data == NULL)
    return FALSE;
  if (got != len)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s has %zu bytes, expected %zu", path, got, len);
      OPENSSL_cleanse (data, got);
      return FALSE;
    }
  memcpy (out, data, len);
  OPENSSL_cleanse (data, got);
  return TRUE;
}

static gboolean pairing_files_present (GUsbDevice *usb, gboolean present[3],
                                       gboolean *pending, GError **error);

void
s00a8_pairing_clear (S00a8Pairing *pairing)
{
  EVP_PKEY_free (pairing->host_key);
  OPENSSL_cleanse (pairing, sizeof (*pairing));
}

/* The certificate carries the host public key little endian: X at 8,
 * Y at 76. */
static void
cert_set_key (guint8 cert[S00A8_CERT_LEN], const guint8 xy[64])
{
  memset (cert, 0, S00A8_CERT_LEN);
  cert[0] = 0x17;             /* key type: P-256 */
  cert[4] = 0x20;             /* coordinate length */
  for (guint i = 0; i < 32; i++)
    {
      cert[8 + i] = xy[31 - i];
      cert[76 + i] = xy[63 - i];
    }
}

static gboolean
key_matches_cert (EVP_PKEY *key, const guint8 cert[S00A8_CERT_LEN])
{
  guint8 point[65], expect[S00A8_CERT_LEN];
  gsize len = 0;

  if (EVP_PKEY_get_octet_string_param (key, OSSL_PKEY_PARAM_PUB_KEY,
                                       point, sizeof (point), &len) != 1 ||
      len != sizeof (point))
    return FALSE;
  cert_set_key (expect, point + 1);
  return CRYPTO_memcmp (expect + 8, cert + 8, 32) == 0 &&
         CRYPTO_memcmp (expect + 76, cert + 76, 32) == 0;
}

static gboolean
sensor_public_key_valid (const guint8 xy[64])
{
  guint8 point[65] = { 0x04 };
  EVP_PKEY_CTX *fromdata = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  EVP_PKEY_CTX *check = NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME,
                                      (char *) "prime256v1", 0),
    OSSL_PARAM_construct_octet_string (OSSL_PKEY_PARAM_PUB_KEY,
                                       point, sizeof (point)),
    OSSL_PARAM_construct_end (),
  };
  EVP_PKEY *key = NULL;
  gboolean ok;

  memcpy (point + 1, xy, 64);
  ok = fromdata != NULL && EVP_PKEY_fromdata_init (fromdata) == 1 &&
       EVP_PKEY_fromdata (fromdata, &key, EVP_PKEY_PUBLIC_KEY, params) == 1;
  if (ok)
    {
      check = EVP_PKEY_CTX_new (key, NULL);
      ok = check != NULL && EVP_PKEY_public_check (check) == 1;
    }
  EVP_PKEY_CTX_free (check);
  EVP_PKEY_free (key);
  EVP_PKEY_CTX_free (fromdata);
  return ok;
}

gboolean
s00a8_pairing_load (GUsbDevice *usb, S00a8Pairing *pairing,
                    gboolean *state_exists, GError **error)
{
  gboolean present[3] = { FALSE };
  gboolean pending = FALSE;
  g_autofree gchar *key_path = pairing_state_path (usb, FILE_HOST_KEY);
  g_autofree gchar *pem = NULL;
  gsize pem_len = 0;
  BIO *bio;

  *state_exists = TRUE;
  if (!pairing_files_present (usb, present, &pending, error))
    return FALSE;
  *state_exists = pending || present[0] || present[1] || present[2];

  if (pending && !(present[0] && present[1] && present[2]))
    {
      /* A marked transaction without all three files was interrupted before
       * the sensor could receive PAIR_DONE. Discard it and start clean. */
      if (!s00a8_pairing_remove_saved (usb, error))
        return FALSE;
      *state_exists = FALSE;
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                           "incomplete saved pairing was removed");
      return FALSE;
    }

  if (!*state_exists)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                           "no saved sensor pairing");
      return FALSE;
    }

  s00a8_pairing_clear (pairing);
  if (!read_exact (usb, FILE_CERT, pairing->cert, S00A8_CERT_LEN, error) ||
      !read_exact (usb, FILE_SENSOR_KEY, pairing->sensor_pub, sizeof (pairing->sensor_pub), error) ||
      !(pem = s00a8_file_read_bounded (key_path, MAX_HOST_KEY_LEN,
                                      &pem_len, error)))
    goto fail;

  bio = BIO_new_mem_buf (pem, (int) MIN (pem_len, (gsize) G_MAXINT));
  pairing->host_key = bio ? PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL) : NULL;
  BIO_free (bio);
  OPENSSL_cleanse (pem, pem_len);

  if (pairing->host_key == NULL || !EVP_PKEY_is_a (pairing->host_key, "EC") ||
      !sensor_public_key_valid (pairing->sensor_pub) ||
      !key_matches_cert (pairing->host_key, pairing->cert))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s does not match the stored certificate", key_path);
      goto fail;
    }
  pairing->pending = pending;
  return TRUE;

fail:
  s00a8_pairing_clear (pairing);
  return FALSE;
}

static gboolean
pairing_save (GUsbDevice *usb, const S00a8Pairing *pairing, GError **error)
{
  BIO *bio = BIO_new (BIO_s_mem ());
  gchar *pem = NULL;
  long len;
  gboolean ok;

  if (bio == NULL || PEM_write_bio_PrivateKey (bio, pairing->host_key, NULL, NULL, 0,
                                               NULL, NULL) != 1)
    {
      BIO_free (bio);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot encode host key");
      return FALSE;
    }
  len = BIO_get_mem_data (bio, &pem);

  /* The key goes last: its presence marks a complete pairing. */
  ok = write_private (usb, FILE_CERT, pairing->cert, S00A8_CERT_LEN, error) &&
       write_private (usb, FILE_SENSOR_KEY, pairing->sensor_pub, sizeof (pairing->sensor_pub), error) &&
       write_private (usb, FILE_HOST_KEY, pem, len, error);
  OPENSSL_cleanse (pem, len);
  BIO_free (bio);
  return ok;
}

static gboolean
unlink_state_file (const gchar *path, GError **error)
{
  if (g_unlink (path) == 0 || errno == ENOENT)
    return TRUE;
  g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
               "cannot remove pairing state %s: %s", path, g_strerror (errno));
  return FALSE;
}

gboolean
s00a8_pairing_remove_saved (GUsbDevice *usb, GError **error)
{
  const gchar *files[] = { FILE_CERT, FILE_SENSOR_KEY, FILE_HOST_KEY };
  g_autofree gchar *cert_path = NULL;
  g_autofree gchar *marker_path = NULL;

  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_autofree gchar *path = pairing_state_path (usb, files[i]);

      if (i == 0)
        cert_path = g_strdup (path);
      if (!unlink_state_file (path, error))
        return FALSE;
    }
  sync_dir_of (cert_path);

  marker_path = pairing_state_path (usb, FILE_PAIR_PENDING);
  if (!unlink_state_file (marker_path, error))
    return FALSE;
  sync_dir_of (marker_path);
  return TRUE;
}

gboolean
s00a8_pairing_commit_pending (GUsbDevice *usb, S00a8Pairing *pairing,
                              GError **error)
{
  g_autofree gchar *marker_path = pairing_state_path (usb, FILE_PAIR_PENDING);

  if (!unlink_state_file (marker_path, error))
    return FALSE;
  sync_dir_of (marker_path);
  pairing->pending = FALSE;
  return TRUE;
}

static gboolean
pairing_files_present (GUsbDevice *usb, gboolean present[3],
                      gboolean *pending, GError **error)
{
  const gchar *files[] = { FILE_CERT, FILE_SENSOR_KEY, FILE_HOST_KEY, FILE_PAIR_PENDING };

  *pending = FALSE;
  for (guint i = 0; i < G_N_ELEMENTS (files); i++)
    {
      g_autofree gchar *path = pairing_state_path (usb, files[i]);
      g_autoptr(GFile) file = g_file_new_for_path (path);
      g_autoptr(GError) query_error = NULL;
      g_autoptr(GFileInfo) info = g_file_query_info (file,
                                                     G_FILE_ATTRIBUTE_STANDARD_TYPE,
                                                     G_FILE_QUERY_INFO_NONE,
                                                     NULL, &query_error);

      if (info != NULL)
        {
          if (i < 3)
            present[i] = TRUE;
          else
            *pending = TRUE;
        }
      else if (!g_error_matches (query_error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND))
        {
          g_propagate_error (error, g_steal_pointer (&query_error));
          return FALSE;
        }
    }
  return TRUE;
}

/* ---- plaintext commands ------------------------------------------------- */

static gboolean
check_cancelled (GCancellable *cancellable, GError **error)
{
  if (cancellable == NULL || !g_cancellable_is_cancelled (cancellable))
    return TRUE;
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                       "device operation cancelled");
  return FALSE;
}

gboolean
s00a8_usb_exchange (GUsbDevice *usb, GCancellable *cancellable,
                    const guint8 *out, gsize out_len,
                    guint8 *in, gsize in_size, gsize *in_len, GError **error)
{
  gsize done = 0;

  if (!check_cancelled (cancellable, error))
    return FALSE;
  if (!g_usb_device_bulk_transfer (usb, S00A8_EP_CMD_OUT, (guint8 *) out, out_len,
                                   &done, S00A8_TIMEOUT_MS, NULL, error))
    return FALSE;
  if (!check_cancelled (cancellable, error))
    return FALSE;
  if (done != out_len)
    {
      if (error != NULL)
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                     "short USB command write: %zu of %zu bytes", done, out_len);
      return FALSE;
    }
  if (!g_usb_device_bulk_transfer (usb, S00A8_EP_CMD_IN, in, in_size, in_len,
                                  S00A8_TIMEOUT_MS, NULL, error))
    return FALSE;
  return check_cancelled (cancellable, error);
}

/* Plaintext command; some answers arrive in two USB packets, so a short
 * second read collects the rest. Requires status 0 and min_len bytes. */
static guint8 *
plain_command (GUsbDevice *usb, GCancellable *cancellable,
               const guint8 *cmd, gsize cmd_len,
               gsize min_len, gsize *out_len, GError **error)
{
  g_autofree guint8 *buf = g_malloc (S00A8_MAX_RESPONSE);
  gsize len = 0, more = 0;

  if (!s00a8_usb_exchange (usb, cancellable, cmd, cmd_len, buf,
                            S00A8_MAX_RESPONSE, &len, error))
    return NULL;
  if (!check_cancelled (cancellable, error))
    return NULL;
  if (len < min_len && len < S00A8_MAX_RESPONSE &&
      g_usb_device_bulk_transfer (usb, S00A8_EP_CMD_IN, buf + len,
                                  S00A8_MAX_RESPONSE - len, &more, 200,
                                  NULL, NULL))
    len += more;
  if (!check_cancelled (cancellable, error))
    return NULL;

  if (len < 2 || len < min_len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "pairing command 0x%02x returned a short response (%zu bytes)",
                   cmd[0], len);
      return NULL;
    }
  if (buf[0] != 0 || buf[1] != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "pairing command 0x%02x failed (status %02x%02x, %zu bytes)",
                   cmd[0], len > 0 ? buf[0] : 0, len > 1 ? buf[1] : 0, len);
      return NULL;
    }
  *out_len = len;
  return g_steal_pointer (&buf);
}

static gboolean
plain_simple (GUsbDevice *usb, GCancellable *cancellable,
              guint8 cmd, GError **error)
{
  gsize len;
  g_autofree guint8 *rsp = plain_command (usb, cancellable, &cmd, 1, 2, &len, error);

  return rsp != NULL;
}

gboolean
s00a8_plain_command (GUsbDevice *usb, GCancellable *cancellable,
                     const guint8 *cmd, gsize cmd_len,
                     GError **error)
{
  gsize len;
  g_autofree guint8 *rsp = plain_command (usb, cancellable, cmd, cmd_len,
                                          2, &len, error);

  return rsp != NULL;
}

/* ---- pairing ------------------------------------------------------------ */

static gboolean
hmac_sha256 (const guint8 *key, gsize key_len, const guint8 *msg, gsize len,
             guint8 out[32])
{
  EVP_MAC *mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new (mac) : NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST, (char *) "SHA256", 0),
    OSSL_PARAM_construct_end (),
  };
  gsize out_len = 0;
  gboolean ok;

  ok = ctx != NULL && EVP_MAC_init (ctx, key, key_len, params) == 1 &&
       EVP_MAC_update (ctx, msg, len) == 1 &&
       EVP_MAC_final (ctx, out, &out_len, 32) == 1 && out_len == 32;
  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok;
}

/* Pairing signing key: P_SHA256(password[0..15], "HS_KEY_PAIR_GEN" ||
 * password[16..31] || aa aa), 32 bytes, read as a little endian scalar. */
static EVP_PKEY *
pairing_signing_key (void)
{
  static const gchar label[] = "HS_KEY_PAIR_GEN";
  guint8 seed[sizeof (label) - 1 + 16 + 2], a[32], msg[32 + sizeof (seed)];
  guint8 le[32], be[32];
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  EVP_PKEY *key = NULL;
  BIGNUM *d = NULL;
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;

  memcpy (seed, label, sizeof (label) - 1);
  memcpy (seed + sizeof (label) - 1, pairing_password + 16, 16);
  seed[sizeof (seed) - 2] = 0xaa;
  seed[sizeof (seed) - 1] = 0xaa;

  /* One P_SHA256 block is exactly the 32 bytes needed. */
  memcpy (msg + 32, seed, sizeof (seed));
  if (!hmac_sha256 (pairing_password, 16, seed, sizeof (seed), a))
    goto out;
  memcpy (msg, a, 32);
  if (!hmac_sha256 (pairing_password, 16, msg, sizeof (msg), le))
    goto out;
  for (guint i = 0; i < 32; i++)
    be[i] = le[31 - i];

  d = BN_bin2bn (be, 32, NULL);
  bld = OSSL_PARAM_BLD_new ();
  if (ctx == NULL || d == NULL || bld == NULL ||
      OSSL_PARAM_BLD_push_utf8_string (bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
      OSSL_PARAM_BLD_push_BN (bld, OSSL_PKEY_PARAM_PRIV_KEY, d) != 1 ||
      (params = OSSL_PARAM_BLD_to_param (bld)) == NULL ||
      EVP_PKEY_fromdata_init (ctx) != 1 ||
      EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_KEYPAIR, params) != 1)
    key = NULL;

out:
  OSSL_PARAM_free (params);
  OSSL_PARAM_BLD_free (bld);
  BN_clear_free (d);
  EVP_PKEY_CTX_free (ctx);
  OPENSSL_cleanse (a, sizeof (a));
  OPENSSL_cleanse (le, sizeof (le));
  OPENSSL_cleanse (be, sizeof (be));
  return key;
}

static guint8 *
ecdsa_sign (EVP_PKEY *key, const guint8 *data, gsize len, gsize *sig_len)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  guint8 *sig = NULL;

  if (ctx && EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, key) == 1 &&
      EVP_DigestSign (ctx, NULL, sig_len, data, len) == 1)
    {
      sig = g_malloc (*sig_len);
      if (EVP_DigestSign (ctx, sig, sig_len, data, len) != 1)
        g_clear_pointer (&sig, g_free);
    }
  EVP_MD_CTX_free (ctx);
  return sig;
}

gboolean
s00a8_pairing_create (GUsbDevice *usb, GCancellable *cancellable,
                      S00a8Pairing *pairing, GError **error)
{
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  EVP_PKEY *sign_key = NULL;
  g_autofree guint8 *sig = NULL;
  g_autofree guint8 *rsp = NULL;
  guint8 req[5 + 4 + CERT_REQ_VALUE] = { CMD_ISSUE_CERT };
  guint8 point[65];
  gsize sig_len = 0, len = 0;
  gboolean ok = FALSE;

  s00a8_pairing_clear (pairing);
  fp_info ("pairing with the sensor");

  if (!plain_simple (usb, cancellable, CMD_ROM_INFO, error) ||
      !plain_simple (usb, cancellable, CMD_PAIR_INIT, error))
    goto out;
  {
    g_autofree guint8 *init = g_malloc (1 + VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN);
    gsize ilen = 0;
    g_autofree guint8 *irsp = NULL;

    init[0] = 0x06;
    memcpy (init + 1, validity_init_msg4_clean_slate_payload,
            VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN);
    irsp = plain_command (usb, cancellable, init,
                          1 + VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN, 2, &ilen, error);
    if (irsp == NULL)
      goto out;
  }

  if (kctx == NULL || EVP_PKEY_keygen_init (kctx) != 1 ||
      EVP_PKEY_CTX_set_group_name (kctx, "prime256v1") != 1 ||
      EVP_PKEY_keygen (kctx, (EVP_PKEY **) &pairing->host_key) != 1 ||
      EVP_PKEY_get_octet_string_param (pairing->host_key, OSSL_PKEY_PARAM_PUB_KEY,
                                       point, sizeof (point), &len) != 1 ||
      len != sizeof (point) ||
      (sign_key = pairing_signing_key ()) == NULL)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                           "cannot create pairing keys");
      goto out;
    }

  /* Request: 4f 00 00 00 00, TLV (tag 5, 444 bytes): certificate,
   * u32 signature length, DER signature, zero padding. */
  cert_set_key (pairing->cert, point + 1);
  sig = ecdsa_sign (sign_key, pairing->cert, S00A8_CERT_LEN, &sig_len);
  if (sig == NULL || sig_len > CERT_REQ_VALUE - S00A8_CERT_LEN - 4)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                           "cannot sign the certificate request");
      goto out;
    }
  req[5] = 0x05;
  req[7] = CERT_REQ_VALUE & 0xff;
  req[8] = CERT_REQ_VALUE >> 8;
  memcpy (req + 9, pairing->cert, S00A8_CERT_LEN);
  req[9 + S00A8_CERT_LEN] = sig_len & 0xff;
  memcpy (req + 9 + S00A8_CERT_LEN + 4, sig, sig_len);

  /* Answer: status, u32 length, the certificate as the sensor signed it. */
  rsp = plain_command (usb, cancellable, req, sizeof (req),
                       6 + S00A8_CERT_LEN, &len, error);
  if (rsp == NULL)
    goto out;
  if (CRYPTO_memcmp (rsp + 6 + 8, pairing->cert + 8, 32) != 0 ||
      CRYPTO_memcmp (rsp + 6 + 76, pairing->cert + 76, 32) != 0)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "sensor certified a different key");
      goto out;
    }
  memcpy (pairing->cert, rsp + 6, S00A8_CERT_LEN);
  g_clear_pointer (&rsp, g_free);

  if (!plain_simple (usb, cancellable, CMD_ROM_INFO, error))
    goto out;
  {
    guint8 cmd = CMD_SENSOR_KEYS;
    rsp = plain_command (usb, cancellable, &cmd, 1,
                         SENSOR_KEY_Y + 32, &len, error);
  }
  if (rsp == NULL)
    goto out;
  for (guint i = 0; i < 32; i++)
    {
      pairing->sensor_pub[i] = rsp[SENSOR_KEY_X + 31 - i];
      pairing->sensor_pub[32 + i] = rsp[SENSOR_KEY_Y + 31 - i];
    }
  if (!sensor_public_key_valid (pairing->sensor_pub))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "sensor returned an invalid P-256 public key");
      goto out;
    }

  /* The marker lets the next open recover an interrupted file transaction
   * or resolve a lost PAIR_DONE reply using the saved key. */
  if (!check_cancelled (cancellable, error) ||
      !write_private (usb, FILE_PAIR_PENDING, "pending", 7, error))
    goto out;
  pairing->pending = TRUE;
  if (!check_cancelled (cancellable, error))
    goto out;
  if (!pairing_save (usb, pairing, error))
    {
      g_autoptr(GError) cleanup_error = NULL;

      if (!s00a8_pairing_remove_saved (usb, &cleanup_error))
        fp_warn ("cannot remove incomplete pairing: %s", cleanup_error->message);
      goto out;
    }
  /* A timeout or disconnect can lose the reply after the sensor committed
   * the pairing. Keep the credentials so the next TLS handshake can resolve
   * that ambiguous outcome. */
  if (!check_cancelled (cancellable, error))
    goto out;
  if (!plain_simple (usb, cancellable, CMD_PAIR_DONE, error))
    {
      if (error != NULL && *error != NULL &&
          (*error)->domain == FP_DEVICE_ERROR &&
          (*error)->code == FP_DEVICE_ERROR_PROTO)
        {
          g_autoptr(GError) cleanup_error = NULL;

          if (s00a8_pairing_remove_saved (usb, &cleanup_error))
            pairing->pending = FALSE;
          else
            fp_warn ("cannot remove rejected pairing: %s", cleanup_error->message);
        }
      goto out;
    }
  {
    g_autoptr(GError) marker_error = NULL;

    if (!s00a8_pairing_commit_pending (usb, pairing, &marker_error))
      fp_warn ("cannot commit pairing marker: %s", marker_error->message);
  }
  ok = TRUE;

out:
  EVP_PKEY_free (sign_key);
  EVP_PKEY_CTX_free (kctx);
  if (!ok)
    s00a8_pairing_clear (pairing);
  else
    fp_info ("paired with the sensor");
  return ok;
}

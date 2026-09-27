/*
 * Synaptics 06cb:00a8 - secure channel
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
 * The sensor accepts commands only inside a TLS 1.2 session with cipher
 * suite TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005), mutually
 * authenticated with the keys exchanged at pairing. The dialect differs
 * from RFC 5246 in a few places, all of which the sensor insists on:
 *
 *  - every client flight starts with the prefix 44 00 00 00;
 *  - ClientHello: 7 byte zero session id, no compression methods, the
 *    extension length is declared 2 bytes short, and extension 0x0004
 *    carries the curve (0x0017 = P-256);
 *  - the ECDH peer key is the static sensor key from pairing (there is no
 *    ServerKeyExchange), and the key block is derived with the same
 *    client_random || server_random seed as the master secret;
 *  - CertificateVerify is a bare DER ECDSA signature over the transcript;
 *  - the server Finished covers the transcript without the client
 *    Finished;
 *  - the record MAC is HMAC-SHA256 over type || version || length ||
 *    fragment, without a sequence number.
 */

#define FP_COMPONENT "synaptics00a8"

#include "drivers_api.h"
#include "s00a8.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#define CT_CHANGE_CIPHER_SPEC   0x14
#define CT_ALERT                0x15
#define CT_HANDSHAKE            0x16
#define CT_APPLICATION_DATA     0x17

#define HS_CLIENT_HELLO         0x01
#define HS_SERVER_HELLO         0x02
#define HS_CERTIFICATE          0x0b
#define HS_CERTIFICATE_REQUEST  0x0d
#define HS_SERVER_HELLO_DONE    0x0e
#define HS_CERTIFICATE_VERIFY   0x0f
#define HS_CLIENT_KEY_EXCHANGE  0x10
#define HS_FINISHED             0x14

enum { TLS_ERROR_UNPAIRED = 1 };

static GQuark
s00a8_tls_error_quark (void)
{
  return g_quark_from_static_string ("s00a8-tls-error");
}

gboolean
s00a8_tls_is_unpaired_error (const GError *error)
{
  return error != NULL && error->domain == s00a8_tls_error_quark () &&
         error->code == TLS_ERROR_UNPAIRED;
}

#define TLS_VERSION             0x0303
#define CIPHER_SUITE            0xc005
#define RECORD_HEADER           5
#define HS_HEADER               4
#define AES_BLOCK               16
#define MAC_LEN                 32
#define VERIFY_DATA_LEN         12
#define MAX_FRAGMENT            0xffff

static const guint8 flight_prefix[4] = { 0x44, 0x00, 0x00, 0x00 };

static void
put_be16 (guint8 *p, guint v)
{
  p[0] = (v >> 8) & 0xff;
  p[1] = v & 0xff;
}

static void
put_be24 (guint8 *p, guint v)
{
  p[0] = (v >> 16) & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = v & 0xff;
}

static guint
get_be16 (const guint8 *p)
{
  return (p[0] << 8) | p[1];
}

static guint
get_be24 (const guint8 *p)
{
  return (p[0] << 16) | (p[1] << 8) | p[2];
}

static GError *
proto_error (const gchar *msg)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", msg);
}

void
s00a8_tls_clear (S00a8Tls *tls)
{
  if (tls->transcript)
    EVP_MD_CTX_free (tls->transcript);
  OPENSSL_cleanse (tls, sizeof (*tls));
}

/* ---- primitives --------------------------------------------------------- */

/* HMAC-SHA256 over a || b. */
static gboolean
hmac2 (const guint8 *key, gsize key_len,
       const guint8 *a, gsize a_len,
       const guint8 *b, gsize b_len,
       guint8        out[MAC_LEN])
{
  EVP_MAC *mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new (mac) : NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST, (char *) "SHA256", 0),
    OSSL_PARAM_construct_end (),
  };
  gsize len = 0;
  gboolean ok;

  ok = ctx != NULL &&
       EVP_MAC_init (ctx, key, key_len, params) == 1 &&
       (a_len == 0 || EVP_MAC_update (ctx, a, a_len) == 1) &&
       (b_len == 0 || EVP_MAC_update (ctx, b, b_len) == 1) &&
       EVP_MAC_final (ctx, out, &len, MAC_LEN) == 1 &&
       len == MAC_LEN;
  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok;
}

/* TLS 1.2 PRF with SHA-256 (RFC 5246, section 5). */
static gboolean
prf (const guint8 *secret, gsize secret_len,
     const gchar  *label,
     const guint8 *seed, gsize seed_len,
     guint8       *out, gsize out_len)
{
  g_autoptr(GByteArray) ls = g_byte_array_new ();
  guint8 a[MAC_LEN], block[MAC_LEN];
  gboolean ok;

  g_byte_array_append (ls, (const guint8 *) label, strlen (label));
  g_byte_array_append (ls, seed, seed_len);

  ok = hmac2 (secret, secret_len, ls->data, ls->len, NULL, 0, a);
  for (gsize done = 0; ok && done < out_len; done += MAC_LEN)
    {
      ok = hmac2 (secret, secret_len, a, MAC_LEN, ls->data, ls->len, block);
      if (!ok)
        break;
      memcpy (out + done, block, MIN ((gsize) MAC_LEN, out_len - done));
      ok = hmac2 (secret, secret_len, a, MAC_LEN, NULL, 0, a);
    }
  OPENSSL_cleanse (a, sizeof (a));
  OPENSSL_cleanse (block, sizeof (block));
  return ok;
}

static gboolean
record_mac (const guint8 *key, guint8 type,
            const guint8 *fragment, gsize len,
            guint8        out[MAC_LEN])
{
  guint8 hdr[RECORD_HEADER] = { type };

  put_be16 (hdr + 1, TLS_VERSION);
  put_be16 (hdr + 3, len);
  return hmac2 (key, 32, hdr, sizeof (hdr), fragment, len, out);
}

static gboolean
aes_cbc (gboolean encrypt, const guint8 key[32], const guint8 iv[AES_BLOCK],
         const guint8 *in, gsize len, guint8 *out)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int n = 0, fin = 0;
  gboolean ok;

  ok = ctx != NULL && len % AES_BLOCK == 0 && len <= G_MAXINT &&
       EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv, encrypt) == 1 &&
       EVP_CIPHER_CTX_set_padding (ctx, 0) == 1 &&
       EVP_CipherUpdate (ctx, out, &n, in, (int) len) == 1 &&
       EVP_CipherFinal_ex (ctx, out + n, &fin) == 1 &&
       (gsize) (n + fin) == len;
  EVP_CIPHER_CTX_free (ctx);
  return ok;
}

/* Encrypt one record: explicit IV, then AES-CBC(fragment || MAC || pad). */
static guint8 *
encrypt_record (S00a8Tls *tls, guint8 type,
                const guint8 *plain, gsize plain_len,
                gsize *out_len)
{
  gsize pad, body_len, frag_len;
  g_autofree guint8 *body = NULL;
  guint8 *rec;

  /* Check before adding overhead: even a SIZE_MAX input must fail safely. */
  if (plain_len > MAX_FRAGMENT - AES_BLOCK - MAC_LEN - AES_BLOCK)
    return NULL;
  pad = AES_BLOCK - (plain_len + MAC_LEN) % AES_BLOCK;
  body_len = plain_len + MAC_LEN + pad;
  frag_len = AES_BLOCK + body_len;

  body = g_malloc (body_len);
  memcpy (body, plain, plain_len);
  if (!record_mac (tls->client_mac_key, type, plain, plain_len, body + plain_len))
    return NULL;
  memset (body + plain_len + MAC_LEN, pad - 1, pad);

  rec = g_malloc (RECORD_HEADER + frag_len);
  rec[0] = type;
  put_be16 (rec + 1, TLS_VERSION);
  put_be16 (rec + 3, frag_len);
  if (RAND_bytes (rec + RECORD_HEADER, AES_BLOCK) != 1 ||
      !aes_cbc (TRUE, tls->client_key, rec + RECORD_HEADER, body, body_len,
                rec + RECORD_HEADER + AES_BLOCK))
    {
      g_free (rec);
      rec = NULL;
    }
  OPENSSL_cleanse (body, body_len);
  *out_len = RECORD_HEADER + frag_len;
  return rec;
}

/* Decrypt and authenticate one record fragment (IV || ciphertext). The
 * padding and the MAC are both checked before anything is reported, and
 * all failures look the same to the caller. */
static guint8 *
decrypt_fragment (S00a8Tls *tls, guint8 type,
                  const guint8 *frag, gsize frag_len,
                  gsize *out_len)
{
  gsize ct_len = frag_len - AES_BLOCK;
  g_autofree guint8 *body = NULL;
  guint8 mac[MAC_LEN] = { 0 };
  guint pad, bad = 0, valid_pad = 0;
  gsize max_pad;
  gsize plain_len;
  guint8 *plain;

  if (frag_len < AES_BLOCK + MAC_LEN + 1 || ct_len % AES_BLOCK != 0)
    return NULL;

  body = g_malloc (ct_len);
  if (!aes_cbc (FALSE, tls->server_key, frag, frag + AES_BLOCK, ct_len, body))
    return NULL;

  /* Authenticate every possible TLS CBC padding length.  A chosen-ciphertext
   * peer must not be able to distinguish padding errors by the amount of
   * padding or the HMAC input length.  The 256 candidates and their HMAC
   * inputs are fixed for a given (public) record length; only their result is
   * selected in constant time using the decrypted padding byte. */
  pad = body[ct_len - 1] + 1;
  max_pad = MIN (ct_len - MAC_LEN, (gsize) 256);
  for (guint candidate = 1; candidate <= 256; candidate++)
    {
      guint mask = 0u - (guint) (candidate == pad);
      gsize candidate_plain_len;
      const guint8 *candidate_mac;

      if (candidate <= max_pad)
        {
          candidate_plain_len = ct_len - MAC_LEN - candidate;
          candidate_mac = body + candidate_plain_len;
          valid_pad |= mask;
        }
      else
        {
          /* Keep invalid candidates in the fixed-work pass without ever
           * deriving an out-of-range plaintext or MAC pointer. */
          candidate_plain_len = 0;
          candidate_mac = body + ct_len - MAC_LEN;
        }

      if (!record_mac (tls->server_mac_key, type, body, candidate_plain_len, mac))
        bad |= mask;
      bad |= (guint) CRYPTO_memcmp (mac, candidate_mac, MAC_LEN) & mask;
    }

  for (guint i = 0; i < 256; i++)
    {
      guint in_padding = 0;

      /* in_padding is all ones when pad >= i + 1.  The inner loop uses
       * public loop counters only, keeping the amount of padding work fixed. */
      for (guint candidate = i + 1; candidate <= 256; candidate++)
        in_padding |= 0u - (guint) (candidate == pad);
      bad |= (body[ct_len - 1 - MIN ((gsize) i, ct_len - 1)] ^ (pad - 1)) & in_padding;
    }
  bad |= ~valid_pad;
  if (bad)
    {
      OPENSSL_cleanse (mac, sizeof (mac));
      OPENSSL_cleanse (body, ct_len);
      return NULL;
    }

  plain_len = ct_len - pad - MAC_LEN;
  plain = g_memdup2 (body, MAX (plain_len, 1));
  OPENSSL_cleanse (mac, sizeof (mac));
  OPENSSL_cleanse (body, ct_len);
  *out_len = plain_len;
  return plain;
}

guint8 *
s00a8_tls_wrap (S00a8Tls *tls, const guint8 *plain, gsize plain_len,
                gsize *out_len, GError **error)
{
  guint8 *rec;

  if (!tls->active)
    {
      g_propagate_error (error, proto_error ("secure channel not established"));
      return NULL;
    }
  rec = encrypt_record (tls, CT_APPLICATION_DATA, plain, plain_len, out_len);
  if (rec == NULL)
    g_propagate_error (error, proto_error ("could not encrypt command"));
  return rec;
}

guint8 *
s00a8_tls_unwrap (S00a8Tls *tls, const guint8 *record, gsize record_len,
                  gsize *out_len, GError **error)
{
  guint8 *plain;
  gsize frag_len;

  if (!tls->active || record_len < RECORD_HEADER ||
      record[0] != CT_APPLICATION_DATA || get_be16 (record + 1) != TLS_VERSION)
    {
      g_propagate_error (error, proto_error ("unexpected response record"));
      return NULL;
    }
  frag_len = get_be16 (record + 3);
  if (RECORD_HEADER + frag_len != record_len)
    {
      g_propagate_error (error, proto_error ("malformed response record"));
      return NULL;
    }
  plain = decrypt_fragment (tls, CT_APPLICATION_DATA, record + RECORD_HEADER,
                            frag_len, out_len);
  if (plain == NULL)
    g_propagate_error (error, proto_error ("response failed authentication"));
  return plain;
}

/* ---- handshake ---------------------------------------------------------- */

static gboolean
transcript_add (S00a8Tls *tls, const guint8 *data, gsize len)
{
  return EVP_DigestUpdate (tls->transcript, data, len) == 1;
}

static gboolean
transcript_hash (S00a8Tls *tls, guint8 out[32])
{
  EVP_MD_CTX *copy = EVP_MD_CTX_new ();
  unsigned int len = 32;
  gboolean ok;

  ok = copy != NULL &&
       EVP_MD_CTX_copy_ex (copy, tls->transcript) == 1 &&
       EVP_DigestFinal_ex (copy, out, &len) == 1 && len == 32;
  EVP_MD_CTX_free (copy);
  return ok;
}

/* Handshake message: type, 24 bit length, body. */
static void
append_hs (GByteArray *out, guint8 type, const guint8 *body, gsize len)
{
  guint8 hdr[HS_HEADER] = { type };

  put_be24 (hdr + 1, len);
  g_byte_array_append (out, hdr, sizeof (hdr));
  g_byte_array_append (out, body, len);
}

static void
append_record (GByteArray *out, guint8 type, const guint8 *frag, gsize len)
{
  guint8 hdr[RECORD_HEADER] = { type };

  put_be16 (hdr + 1, TLS_VERSION);
  put_be16 (hdr + 3, len);
  g_byte_array_append (out, hdr, sizeof (hdr));
  g_byte_array_append (out, frag, len);
}

static GByteArray *
client_hello (S00a8Tls *tls)
{
  static const guint8 suites[] = { 0xc0, 0x05, 0x00, 0x3d, 0x00, 0x8d };
  static const guint8 extensions[] = {
    0x00, 0x04, 0x00, 0x02, 0x00, 0x17,   /* curve P-256 */
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,   /* uncompressed points */
  };
  g_autoptr(GByteArray) body = g_byte_array_new ();
  g_autoptr(GByteArray) hs = g_byte_array_new ();
  GByteArray *out = g_byte_array_new ();
  guint8 tmp[8] = { 0 };

  put_be16 (tmp, TLS_VERSION);
  g_byte_array_append (body, tmp, 2);
  g_byte_array_append (body, tls->client_random, 32);
  tmp[0] = 7;                                         /* session id */
  memset (tmp + 1, 0, 7);
  g_byte_array_append (body, tmp, 8);
  put_be16 (tmp, sizeof (suites));
  g_byte_array_append (body, tmp, 2);
  g_byte_array_append (body, suites, sizeof (suites));
  tmp[0] = 0;                                         /* no compression */
  g_byte_array_append (body, tmp, 1);
  put_be16 (tmp, sizeof (extensions) - 2);
  g_byte_array_append (body, tmp, 2);
  g_byte_array_append (body, extensions, sizeof (extensions));

  append_hs (hs, HS_CLIENT_HELLO, body->data, body->len);
  if (!transcript_add (tls, hs->data, hs->len))
    {
      g_byte_array_unref (out);
      return NULL;
    }

  g_byte_array_append (out, flight_prefix, sizeof (flight_prefix));
  append_record (out, CT_HANDSHAKE, hs->data, hs->len);
  return out;
}

/* ServerHello, CertificateRequest, ServerHelloDone in one record. */
static gboolean
parse_server_flight (S00a8Tls *tls, const guint8 *rsp, gsize rsp_len, GError **error)
{
  gboolean hello = FALSE, request = FALSE, done = FALSE;
  gsize len, off;

  if (rsp_len < RECORD_HEADER || rsp[0] != CT_HANDSHAKE ||
      get_be16 (rsp + 1) != TLS_VERSION)
    {
      g_propagate_error (error, proto_error ("sensor did not answer ClientHello"));
      return FALSE;
    }
  len = get_be16 (rsp + 3);
  if (RECORD_HEADER + len != rsp_len)
    {
      g_propagate_error (error, proto_error ("truncated ServerHello record"));
      return FALSE;
    }
  rsp += RECORD_HEADER;

  for (off = 0; off + HS_HEADER <= len;)
    {
      guint8 type = rsp[off];
      gsize mlen = get_be24 (rsp + off + 1);
      const guint8 *m = rsp + off + HS_HEADER;

      if (off + HS_HEADER + mlen > len)
        break;
      if (!transcript_add (tls, rsp + off, HS_HEADER + mlen))
        {
          g_propagate_error (error, proto_error ("handshake hash update failed"));
          return FALSE;
        }

      switch (type)
        {
        case HS_SERVER_HELLO:
          /* version, random, session id, suite, compression */
          if (hello || request || done || mlen < 35 || get_be16 (m) != TLS_VERSION ||
              35 + (gsize) m[34] + 3 > mlen ||
              get_be16 (m + 35 + m[34]) != CIPHER_SUITE ||
              m[37 + m[34]] != 0)
            {
              g_propagate_error (error, proto_error ("unexpected ServerHello"));
              return FALSE;
            }
          memcpy (tls->server_random, m + 2, 32);
          hello = TRUE;
          break;

        case HS_CERTIFICATE_REQUEST:
          if (!hello || request || done)
            {
              g_propagate_error (error, proto_error ("unexpected CertificateRequest order"));
              return FALSE;
            }
          request = TRUE;
          break;

        case HS_SERVER_HELLO_DONE:
          if (!hello || !request || done || mlen != 0)
            {
              g_propagate_error (error, proto_error ("unexpected ServerHelloDone"));
              return FALSE;
            }
          done = TRUE;
          break;

        case HS_CERTIFICATE:
          /* Only sent by a sensor that has no pairing with this host. */
          g_set_error_literal (error, s00a8_tls_error_quark (), TLS_ERROR_UNPAIRED,
                               "sensor is not paired with this host");
          return FALSE;

        default:
          g_propagate_error (error, proto_error ("unexpected handshake message"));
          return FALSE;
        }
      off += HS_HEADER + mlen;
    }

  if (off != len || !hello || !request || !done)
    {
      g_propagate_error (error, proto_error ("incomplete server handshake flight"));
      return FALSE;
    }
  return TRUE;
}

static EVP_PKEY *
ec_key_generate (void)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  EVP_PKEY *key = NULL;

  if (ctx == NULL || EVP_PKEY_keygen_init (ctx) != 1 ||
      EVP_PKEY_CTX_set_group_name (ctx, "prime256v1") != 1 ||
      EVP_PKEY_keygen (ctx, &key) != 1)
    key = NULL;
  EVP_PKEY_CTX_free (ctx);
  return key;
}

static EVP_PKEY *
ec_public_key (const guint8 xy[64])
{
  guint8 point[65] = { 0x04 };
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME, (char *) "prime256v1", 0),
    OSSL_PARAM_construct_octet_string (OSSL_PKEY_PARAM_PUB_KEY, point, sizeof (point)),
    OSSL_PARAM_construct_end (),
  };
  EVP_PKEY *key = NULL;

  memcpy (point + 1, xy, 64);
  if (ctx == NULL || EVP_PKEY_fromdata_init (ctx) != 1 ||
      EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1)
    key = NULL;
  EVP_PKEY_CTX_free (ctx);
  return key;
}

/* Uncompressed public point of a key, without the 0x04 prefix. */
static gboolean
ec_public_xy (EVP_PKEY *key, guint8 xy[64])
{
  guint8 point[65];
  gsize len = 0;

  if (EVP_PKEY_get_octet_string_param (key, OSSL_PKEY_PARAM_PUB_KEY,
                                       point, sizeof (point), &len) != 1 ||
      len != sizeof (point) || point[0] != 0x04)
    return FALSE;
  memcpy (xy, point + 1, 64);
  return TRUE;
}

static gboolean
ecdh (EVP_PKEY *priv, EVP_PKEY *peer, guint8 out[32])
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (priv, NULL);
  gsize len = 32;
  gboolean ok;

  ok = ctx != NULL &&
       EVP_PKEY_derive_init (ctx) == 1 &&
       EVP_PKEY_derive_set_peer (ctx, peer) == 1 &&
       EVP_PKEY_derive (ctx, out, &len) == 1 && len == 32;
  EVP_PKEY_CTX_free (ctx);
  return ok;
}

/* DER ECDSA signature of an already computed SHA-256 digest. */
static guint8 *
ecdsa_sign_digest (EVP_PKEY *key, const guint8 digest[32], gsize *out_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (key, NULL);
  guint8 *sig = NULL;
  gsize len = 0;

  if (ctx != NULL && EVP_PKEY_sign_init (ctx) == 1 &&
      EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ()) == 1 &&
      EVP_PKEY_sign (ctx, NULL, &len, digest, 32) == 1)
    {
      sig = g_malloc (len);
      if (EVP_PKEY_sign (ctx, sig, &len, digest, 32) != 1)
        g_clear_pointer (&sig, g_free);
    }
  EVP_PKEY_CTX_free (ctx);
  *out_len = len;
  return sig;
}

static gboolean
derive_keys (S00a8Tls *tls, const guint8 pms[32])
{
  guint8 seed[64], block[128];
  gboolean ok;

  memcpy (seed, tls->client_random, 32);
  memcpy (seed + 32, tls->server_random, 32);
  ok = prf (pms, 32, "master secret", seed, sizeof (seed),
            tls->master_secret, sizeof (tls->master_secret)) &&
       prf (tls->master_secret, sizeof (tls->master_secret), "key expansion",
            seed, sizeof (seed), block, sizeof (block));
  if (ok)
    {
      memcpy (tls->client_mac_key, block, 32);
      memcpy (tls->server_mac_key, block + 32, 32);
      memcpy (tls->client_key, block + 64, 32);
      memcpy (tls->server_key, block + 96, 32);
    }
  OPENSSL_cleanse (seed, sizeof (seed));
  OPENSSL_cleanse (block, sizeof (block));
  return ok;
}

/* Certificate, ClientKeyExchange, CertificateVerify, ChangeCipherSpec and
 * the encrypted Finished, in one flight. */
static GByteArray *
client_flight (S00a8Tls *tls, const S00a8Pairing *pairing, EVP_PKEY *eph,
               GError **error)
{
  static const guint8 ccs[] = { 0x01 };
  g_autoptr(GByteArray) hs = g_byte_array_new ();
  g_autofree guint8 *sig = NULL;
  g_autofree guint8 *fin_rec = NULL;
  GByteArray *out;
  guint8 cert[8 + S00A8_CERT_LEN];
  guint8 cke[65] = { 0x04 };
  guint8 digest[32], finished[HS_HEADER + VERIFY_DATA_LEN] = { HS_FINISHED };
  gsize sig_len = 0, fin_len = 0, mark;

  /* Certificate list with the one certificate the sensor issued; bytes
   * 6..7 of the certificate entry echo client_random[4..5]. */
  put_be24 (cert, S00A8_CERT_LEN);
  put_be24 (cert + 3, S00A8_CERT_LEN);
  cert[6] = tls->client_random[4];
  cert[7] = tls->client_random[5];
  memcpy (cert + 8, pairing->cert, S00A8_CERT_LEN);
  append_hs (hs, HS_CERTIFICATE, cert, sizeof (cert));

  if (!ec_public_xy (eph, cke + 1))
    goto fail;
  append_hs (hs, HS_CLIENT_KEY_EXCHANGE, cke, sizeof (cke));

  if (!transcript_add (tls, hs->data, hs->len))
    goto fail;
  if (!transcript_hash (tls, digest) ||
      (sig = ecdsa_sign_digest (pairing->host_key, digest, &sig_len)) == NULL)
    goto fail;
  mark = hs->len;
  append_hs (hs, HS_CERTIFICATE_VERIFY, sig, sig_len);
  if (!transcript_add (tls, hs->data + mark, hs->len - mark))
    goto fail;

  put_be24 (finished + 1, VERIFY_DATA_LEN);
  if (!transcript_hash (tls, digest) ||
      !prf (tls->master_secret, sizeof (tls->master_secret), "client finished",
            digest, sizeof (digest), finished + HS_HEADER, VERIFY_DATA_LEN))
    goto fail;
  fin_rec = encrypt_record (tls, CT_HANDSHAKE, finished, sizeof (finished), &fin_len);
  if (fin_rec == NULL)
    goto fail;

  out = g_byte_array_new ();
  g_byte_array_append (out, flight_prefix, sizeof (flight_prefix));
  append_record (out, CT_HANDSHAKE, hs->data, hs->len);
  append_record (out, CT_CHANGE_CIPHER_SPEC, ccs, sizeof (ccs));
  g_byte_array_append (out, fin_rec, fin_len);
  return out;

fail:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                      "could not build handshake flight"));
  return NULL;
}

/* ChangeCipherSpec followed by the encrypted server Finished. A warning
 * alert may precede it; a fatal alert ends the handshake. */
static gboolean
check_server_finished (S00a8Tls *tls, const guint8 *rsp, gsize rsp_len, GError **error)
{
  g_autofree guint8 *fin = NULL;
  guint8 digest[32], expect[VERIFY_DATA_LEN];
  gsize len, fin_len = 0;

  while (rsp_len >= RECORD_HEADER + 2 && rsp[0] == CT_ALERT)
    {
      len = get_be16 (rsp + 3);
      if (get_be16 (rsp + 1) != TLS_VERSION || len != 2 ||
          RECORD_HEADER + len > rsp_len)
        {
          g_propagate_error (error, proto_error ("malformed TLS alert"));
          return FALSE;
        }
      if (rsp[RECORD_HEADER] == 2)
        {
          g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "sensor rejected the handshake (alert %u)",
                                                              rsp[RECORD_HEADER + 1]));
          return FALSE;
        }
      len += RECORD_HEADER;
      rsp += len;
      rsp_len -= len;
    }

  if (rsp_len < 6 || rsp[0] != CT_CHANGE_CIPHER_SPEC ||
      get_be16 (rsp + 1) != TLS_VERSION || get_be16 (rsp + 3) != 1 ||
      rsp[RECORD_HEADER] != 1)
    {
      g_propagate_error (error, proto_error ("expected ChangeCipherSpec"));
      return FALSE;
    }
  rsp += 6;
  rsp_len -= 6;
  if (rsp_len < RECORD_HEADER || rsp[0] != CT_HANDSHAKE ||
      get_be16 (rsp + 1) != TLS_VERSION ||
      RECORD_HEADER + get_be16 (rsp + 3) != rsp_len)
    {
      g_propagate_error (error, proto_error ("expected server Finished"));
      return FALSE;
    }

  fin = decrypt_fragment (tls, CT_HANDSHAKE, rsp + RECORD_HEADER,
                          get_be16 (rsp + 3), &fin_len);
  if (fin == NULL || fin_len != HS_HEADER + VERIFY_DATA_LEN ||
      fin[0] != HS_FINISHED || get_be24 (fin + 1) != VERIFY_DATA_LEN ||
      !transcript_hash (tls, digest) ||
      !prf (tls->master_secret, sizeof (tls->master_secret), "server finished",
            digest, sizeof (digest), expect, sizeof (expect)) ||
      CRYPTO_memcmp (expect, fin + HS_HEADER, VERIFY_DATA_LEN) != 0)
    {
      g_propagate_error (error, proto_error ("server Finished did not verify"));
      return FALSE;
    }
  return TRUE;
}

gboolean
s00a8_tls_handshake (GUsbDevice *usb, GCancellable *cancellable, S00a8Tls *tls,
                     const S00a8Pairing *pairing, GError **error)
{
  g_autoptr(GByteArray) hello = NULL;
  g_autoptr(GByteArray) flight = NULL;
  g_autofree guint8 *rsp = g_malloc (S00A8_MAX_RESPONSE);
  EVP_PKEY *eph = NULL, *peer = NULL;
  guint8 pms[32];
  gsize rsp_len = 0;
  guint32 now = (guint32) (g_get_real_time () / G_USEC_PER_SEC);
  gboolean ok = FALSE;

  s00a8_tls_clear (tls);
  tls->transcript = EVP_MD_CTX_new ();
  if (tls->transcript == NULL ||
      EVP_DigestInit_ex (tls->transcript, EVP_sha256 (), NULL) != 1 ||
      RAND_bytes (tls->client_random + 4, 28) != 1)
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "crypto initialisation failed"));
      goto out;
    }
  tls->client_random[0] = now >> 24;
  tls->client_random[1] = now >> 16;
  tls->client_random[2] = now >> 8;
  tls->client_random[3] = now;

  hello = client_hello (tls);
  if (hello == NULL)
    {
      g_propagate_error (error, proto_error ("handshake hash update failed"));
      goto out;
    }
  if (!s00a8_usb_exchange (usb, cancellable, hello->data, hello->len,
                           rsp, S00A8_MAX_RESPONSE,
                           &rsp_len, error) ||
      !parse_server_flight (tls, rsp, rsp_len, error))
    goto out;

  eph = ec_key_generate ();
  peer = ec_public_key (pairing->sensor_pub);
  if (eph == NULL || peer == NULL || !ecdh (eph, peer, pms) || !derive_keys (tls, pms))
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "key agreement failed"));
      goto out;
    }

  flight = client_flight (tls, pairing, eph, error);
  if (flight == NULL ||
      !s00a8_usb_exchange (usb, cancellable, flight->data, flight->len,
                           rsp, S00A8_MAX_RESPONSE,
                           &rsp_len, error) ||
      !check_server_finished (tls, rsp, rsp_len, error))
    goto out;

  tls->active = TRUE;
  ok = TRUE;

out:
  OPENSSL_cleanse (pms, sizeof (pms));
  EVP_PKEY_free (eph);
  EVP_PKEY_free (peer);
  g_clear_pointer ((EVP_MD_CTX **) &tls->transcript, EVP_MD_CTX_free);
  if (!ok)
    s00a8_tls_clear (tls);
  return ok;
}

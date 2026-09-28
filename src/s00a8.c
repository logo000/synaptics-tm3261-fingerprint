/*
 * Synaptics 06cb:00a8 fingerprint reader
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
 * The Synaptics 06cb:00a8 is a small (about 7 x 3 mm) press sensor with no
 * on-chip matching. The host opens a mutually authenticated TLS session
 * (s00a8-tls.c), pairing once with the sensor if needed (s00a8-pair.c),
 * then loads a capture program (s00a8-program.c) and reads raw frames that
 * decode to a 144 x 56 ridge image (s00a8-image.c). Enrolment stitches
 * several presses into a mosaic and verification correlates against it
 * (s00a8-match.c), because a single press covers too little of the finger
 * for a minutiae matcher.
 *
 * Templates are stored in the print as FPI_PRINT_RAW data of the form
 * (u version, u count, ay templates, ad poses).
 */

#define FP_COMPONENT "synaptics00a8"

#include "drivers_api.h"
#include "s00a8.h"

#include <glib/gstdio.h>
#include <math.h>

struct _FpiDeviceSynaptics00a8
{
  FpDevice       parent;

  S00a8Tls       tls;
  S00a8Pairing   pairing;
  guint8         factory_cal[S00A8_FACTORY_CAL_LEN];
  gboolean       have_factory_cal;

  FpiSsm        *task_ssm;

  /* Capture loop working set (144 x 56 floats). */
  gfloat        *img;
  gfloat        *baseline;
  gfloat        *previous;
  guint8        *cal_frame;      /* raw finger-free frame for offset lines */
  gint8         *template;       /* prepared ridge template of the last press */
  gdouble        coverage;
  gboolean       have_cal;
  gboolean       have_baseline;
  gboolean       have_previous;
  gboolean       await_lift;
  guint          stable;
  gint           done_state;
  guint          busy_retries;
  guint          drain_left;

  /* Enrolment accumulation. */
  S00a8Aligner  *aligner;
  GByteArray    *templates;
  guint          enroll_done;
  guint          enroll_tries;

  FpiMatchResult verify_result;
  FpPrint       *identify_match; /* Borrowed from the active gallery. */
};

G_DECLARE_FINAL_TYPE (FpiDeviceSynaptics00a8, fpi_device_synaptics00a8, FPI,
                      DEVICE_SYNAPTICS00A8, FpDevice)
G_DEFINE_TYPE (FpiDeviceSynaptics00a8, fpi_device_synaptics00a8, FP_TYPE_DEVICE)

#define ENROLL_STAGES        15
#define ENROLL_MAX_TRIES     (ENROLL_STAGES * 4)

#define MIN_COVERAGE         0.45
#define MATCH_THRESHOLD      0.60
#define NORM_THRESHOLD       0.18

#define CAPTURE_FRAMES       2
#define CAPTURE_LINES        (CAPTURE_FRAMES * S00A8_LINES_PER_FRAME + 1)
#define POLL_INTERVAL_MS     40

#define PRESENT_DIFF         6.0
#define LIFTED_DIFF          2.5
#define REBASE_DIFF          1.5
#define STABLE_DIFF          1.2
#define STABLE_FRAMES        12

#define PRINT_VERSION        1
#define MAX_TEMPLATES        ENROLL_STAGES

static const FpIdEntry id_table[] = {
  { .vid = 0x06cb, .pid = 0x00a8 },
  { .vid = 0, .pid = 0 },
};

/* ---- encrypted command exchange ----------------------------------------- */

typedef void (*S00a8ReplyCb) (FpDevice     *dev,
                              FpiSsm       *ssm,
                              const guint8 *body,
                              gsize         body_len,
                              gpointer      user_data);

typedef struct
{
  FpiSsm       *ssm;
  S00a8ReplyCb  cb;
  gpointer      cb_data;
} ExchangeCtx;

static void
exchange_recv_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                  gpointer user_data, GError *error)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  g_autofree ExchangeCtx *ctx = user_data;
  g_autofree guint8 *body = NULL;
  gsize body_len = 0;

  if (error)
    {
      fpi_ssm_mark_failed (ctx->ssm, error);
      return;
    }
  body = s00a8_tls_unwrap (&self->tls, transfer->buffer, transfer->actual_length,
                           &body_len, &error);
  if (body == NULL)
    {
      fpi_ssm_mark_failed (ctx->ssm, error);
      return;
    }
  if (ctx->cb)
    ctx->cb (dev, ctx->ssm, body, body_len, ctx->cb_data);
  else
    fpi_ssm_next_state (ctx->ssm);
}

static void
exchange_send_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                  gpointer user_data, GError *error)
{
  FpiUsbTransfer *in;
  ExchangeCtx *ctx = user_data;

  if (error)
    {
      FpiSsm *ssm = ctx->ssm;
      g_free (ctx);
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (transfer->actual_length != transfer->length)
    {
      FpiSsm *ssm = ctx->ssm;
      g_free (ctx);
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "short TLS record USB write"));
      return;
    }
  in = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (in, S00A8_EP_CMD_IN, S00A8_MAX_RESPONSE);
  fpi_usb_transfer_submit (in, S00A8_TIMEOUT_MS, fpi_device_get_cancellable (dev),
                           exchange_recv_cb, user_data);
}

/* Encrypt `plain`, send it, read and decrypt the reply. With cb == NULL
 * the SSM simply advances; otherwise cb owns the transition. */
static void
s00a8_exchange (FpiSsm *ssm, FpDevice *dev, const gchar *label,
                const guint8 *plain, gsize plain_len,
                S00a8ReplyCb cb, gpointer cb_data)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  g_autoptr(GError) error = NULL;
  FpiUsbTransfer *out;
  ExchangeCtx *ctx;
  guint8 *record;
  gsize record_len = 0;

  record = s00a8_tls_wrap (&self->tls, plain, plain_len, &record_len, &error);
  if (record == NULL)
    {
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }
  ctx = g_new0 (ExchangeCtx, 1);
  ctx->ssm = ssm;
  ctx->cb = cb;
  ctx->cb_data = cb_data;
  fp_dbg ("sending %s", label);

  out = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk_full (out, S00A8_EP_CMD_OUT, record, record_len, g_free);
  fpi_usb_transfer_submit (out, S00A8_TIMEOUT_MS, fpi_device_get_cancellable (dev),
                           exchange_send_cb, ctx);
}

static guint16
status_of (const guint8 *body, gsize len)
{
  return len >= 2 ? (body[0] | (body[1] << 8)) : 0xffff;
}

static gboolean
command_status_ok (FpiSsm *ssm, const guint8 *body, gsize len,
                   const gchar *command)
{
  guint16 status = status_of (body, len);

  if (status == 0)
    return TRUE;
  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                       "%s refused (0x%04x)", command, status));
  return FALSE;
}

/* ---- session preparation ------------------------------------------------ */

/* Factory calibration: command 0x6f, tag 0x0e00, returns entries of
 * {u32 ptr, u16 len, u16 tag, u16 subtag, u16 flags} + value. Subtag 3
 * carries a 4 byte header and then one calibration value per image row. */
static void
factory_bits_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body, gsize len,
                 gpointer user_data)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  gsize pos = 10;
  guint32 entries;

  self->have_factory_cal = FALSE;
  if (len >= 10 && body[0] == 0 && body[1] == 0)
    {
      entries = body[6] | (body[7] << 8) | (body[8] << 16) | ((guint32) body[9] << 24);
      for (guint32 i = 0; i < entries && pos + 12 <= len; i++)
        {
          guint16 vlen = body[pos + 4] | (body[pos + 5] << 8);
          guint16 subtag = body[pos + 8] | (body[pos + 9] << 8);

          if (pos + 12 + vlen > len)
            break;
          if (subtag == 3 && vlen == 4 + S00A8_FACTORY_CAL_LEN)
            {
              memcpy (self->factory_cal, body + pos + 12 + 4, S00A8_FACTORY_CAL_LEN);
              self->have_factory_cal = TRUE;
            }
          pos += 12 + vlen;
        }
    }
  fp_dbg ("factory calibration: %s",
          self->have_factory_cal ? "from sensor" : "constant fallback");
  fpi_ssm_next_state (ssm);
}

static void config_blob_send (FpiSsm *ssm, FpDevice *dev);
static void config_after_stop_cb (FpDevice *dev, FpiSsm *ssm,
                                  const guint8 *body, gsize len,
                                  gpointer user_data);

static void
config_drain_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                 gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  /* Keep draining EP 0x82 until it is empty or the bound is reached, then
   * resend the blob. Bounded so a continuously streaming device cannot
   * stall the action, and cancellable so it aborts on cancellation. */
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  if (error == NULL && transfer->actual_length > 0 && self->drain_left-- > 0)
    {
      FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

      fpi_usb_transfer_fill_bulk (t, S00A8_EP_IMAGE_IN, 0x20000);
      t->short_is_error = FALSE;
      fpi_usb_transfer_submit (t, 300, fpi_device_get_cancellable (dev),
                               config_drain_cb, ssm);
      return;
    }
  g_clear_error (&error);
  {
    guint8 stop = 0x04;

    s00a8_exchange (ssm, dev, "config-recover-stop", &stop, 1,
                    config_after_stop_cb, NULL);
  }
}

static void
config_after_stop_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body,
                      gsize len, gpointer user_data)
{
  if (!command_status_ok (ssm, body, len, "capture stop"))
    return;
  config_blob_send (ssm, dev);
}

static void
config_blob_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body, gsize len,
                gpointer user_data)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  guint16 status = status_of (body, len);

  /* 0x04aa: the configuration is already active and stays until the
   * sensor restarts. 0x04e5: a capture from an aborted session is still
   * running; stop it and resend. */
  if (status == 0x0000 || status == 0x04aa)
    {
      self->busy_retries = 0;
      fpi_ssm_next_state (ssm);
      return;
    }
  if (status == 0x04e5 && self->busy_retries++ < 3)
    {
      FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

      self->drain_left = 256;
      fpi_usb_transfer_fill_bulk (t, S00A8_EP_IMAGE_IN, 0x20000);
      t->short_is_error = FALSE;
      fpi_usb_transfer_submit (t, 300, fpi_device_get_cancellable (dev),
                               config_drain_cb, ssm);
      return;
    }
  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                       "scan configuration refused (0x%04x)", status));
}

static void
config_blob_send (FpiSsm *ssm, FpDevice *dev)
{
  g_autofree guint8 *cmd = g_malloc (1 + VALIDITY_ENROLL_HOSTPART_BLOB_LEN);

  cmd[0] = 0x06;
  memcpy (cmd + 1, validity_enroll_hostpart_blob, VALIDITY_ENROLL_HOSTPART_BLOB_LEN);
  s00a8_exchange (ssm, dev, "config-blob", cmd,
                  1 + VALIDITY_ENROLL_HOSTPART_BLOB_LEN, config_blob_cb, NULL);
}

static void
prep_status_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body, gsize len,
                gpointer user_data)
{
  if (command_status_ok (ssm, body, len, user_data))
    fpi_ssm_next_state (ssm);
}

enum {
  PREP_ROM_INFO,
  PREP_IDENTIFY,
  PREP_FACTORY_BITS,
  PREP_CONFIG,
  PREP_STATES,
};

static void
prep_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case PREP_ROM_INFO:
      {
        guint8 cmd = 0x01;
        s00a8_exchange (ssm, dev, "rom-info", &cmd, 1,
                        prep_status_cb, (gpointer) "ROM info");
        break;
      }
    case PREP_IDENTIFY:
      {
        guint8 cmd = 0x75;
        s00a8_exchange (ssm, dev, "identify", &cmd, 1,
                        prep_status_cb, (gpointer) "identify");
        break;
      }
    case PREP_FACTORY_BITS:
      {
        guint8 cmd[9] = { 0x6f, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        s00a8_exchange (ssm, dev, "factory-bits", cmd, sizeof (cmd),
                        factory_bits_cb, NULL);
        break;
      }
    case PREP_CONFIG:
      config_blob_send (ssm, dev);
      break;
    }
}

/* ---- capture loop ------------------------------------------------------- *
 *
 * Short finite captures are taken repeatedly. The first finger-free frame
 * becomes the calibration frame for the offset lines, the next one the
 * baseline the presence difference is measured against. A finger is
 * present when the mean absolute difference to the baseline exceeds
 * PRESENT_DIFF; after an accepted press the finger must be lifted before
 * the next capture. On a finger image the loop prepares a ridge template
 * and jumps the task SSM to done_state.
 */

static gchar *
baseline_path (GUsbDevice *usb)
{
  return s00a8_device_state_path (usb, "capture-reference-v1.bin");
}

static void
remove_saved_baseline (GUsbDevice *usb)
{
  g_autofree gchar *path = baseline_path (usb);

  if (g_unlink (path) != 0 && errno != ENOENT)
    fp_warn ("cannot remove stale baseline %s: %s", path, g_strerror (errno));
}

/* Persist the uncorrected calibration and the corrected baseline together.
 * A corrected baseline is NOT a valid input for the sensor's 0x85 offsets.
 * Old baseline.bin files lack that calibration and must not be reused. */
static gboolean
load_capture_reference (FpiDeviceSynaptics00a8 *self, GUsbDevice *usb)
{
  g_autofree gchar *path = baseline_path (usb);
  g_autofree gchar *saved = NULL;
  const gsize size = S00A8_PIXELS * (sizeof (guint8) + sizeof (gfloat));
  gsize len = 0;

  saved = s00a8_file_read_bounded (path, size, &len, NULL);
  if (saved == NULL || len != size)
    return FALSE;
  for (guint i = 0; i < S00A8_PIXELS; i++)
    {
      gfloat value;
      memcpy (&value, saved + S00A8_PIXELS + i * sizeof value, sizeof value);
      if (!isfinite (value) || value < 0 || value > 255)
        return FALSE;
    }
  memcpy (self->cal_frame, saved, S00A8_PIXELS);
  memcpy (self->baseline, saved + S00A8_PIXELS, S00A8_PIXELS * sizeof (gfloat));
  self->have_cal = TRUE;
  self->have_baseline = TRUE;
  fp_info ("loaded paired raw calibration and corrected baseline");
  return TRUE;
}

static void
save_capture_reference (FpiDeviceSynaptics00a8 *self, GUsbDevice *usb)
{
  g_autofree gchar *path = baseline_path (usb);
  const gsize size = S00A8_PIXELS * (sizeof (guint8) + sizeof (gfloat));
  g_autofree gchar *data = g_malloc (size);
  g_autoptr(GError) error = NULL;

  memcpy (data, self->cal_frame, S00A8_PIXELS);
  memcpy (data + S00A8_PIXELS, self->baseline, S00A8_PIXELS * sizeof (gfloat));
  if (!g_file_set_contents_full (path, data, size,
                                  G_FILE_SET_CONTENTS_CONSISTENT, 0600, &error))
    fp_warn ("cannot save capture reference: %s", error->message);
}

static void capture_send (FpiSsm *ssm, FpDevice *dev);

static void
capture_timeout_cb (FpDevice *dev, gpointer user_data)
{
  capture_send ((FpiSsm *) user_data, dev);
}

static void
capture_schedule (FpiSsm *ssm, FpDevice *dev)
{
  fpi_device_add_timeout (dev, POLL_INTERVAL_MS, capture_timeout_cb, ssm, NULL);
}

static void
capture_finger_ready (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  g_autofree gfloat *px = g_new (gfloat, S00A8_PIXELS);

  s00a8_image_demux (self->img, self->baseline, px);
  self->coverage = s00a8_match_prepare (px, self->template);
  self->await_lift = TRUE;
  fpi_device_report_finger_status (dev, FP_FINGER_STATUS_PRESENT);
  fpi_ssm_jump_to_state (ssm, self->done_state);
}

static void
capture_decide (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  gdouble change, diff;

  change = self->have_previous ? s00a8_image_difference (self->img, self->previous) : 1e9;
  self->stable = change < STABLE_DIFF ? self->stable + 1 : 0;
  memcpy (self->previous, self->img, S00A8_PIXELS * sizeof (gfloat));
  self->have_previous = TRUE;

  if (!self->have_cal)
    {
      if (self->stable == 1 &&
          (!self->have_baseline ||
           s00a8_image_difference (self->img, self->baseline) < PRESENT_DIFF))
        {
          for (guint i = 0; i < S00A8_PIXELS; i++)
            self->cal_frame[i] = (guint8) CLAMP (lrintf (self->img[i]), 0, 255);
          self->have_cal = TRUE;
          self->have_previous = FALSE;
          self->stable = 0;
          fp_info ("capture calibration acquired");
        }
      capture_schedule (ssm, dev);
      return;
    }

  if (!self->have_baseline)
    {
      if (self->stable >= 1)
        {
          memcpy (self->baseline, self->img, S00A8_PIXELS * sizeof (gfloat));
          self->have_baseline = TRUE;
          save_capture_reference (self, fpi_device_get_usb_device (dev));
          fp_info ("capture baseline acquired");
          fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NEEDED);
        }
      capture_schedule (ssm, dev);
      return;
    }

  diff = s00a8_image_difference (self->img, self->baseline);

  if (self->await_lift)
    {
      if (diff < LIFTED_DIFF ||
          (diff < PRESENT_DIFF && self->stable >= STABLE_FRAMES))
        {
          if (diff >= LIFTED_DIFF)
            memcpy (self->baseline, self->img, S00A8_PIXELS * sizeof (gfloat));
          self->await_lift = FALSE;
          fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NEEDED);
        }
      capture_schedule (ssm, dev);
      return;
    }

  if (diff >= PRESENT_DIFF)
    {
      capture_finger_ready (ssm, dev);
      return;
    }
  if (diff < REBASE_DIFF)
    for (guint i = 0; i < S00A8_PIXELS; i++)
      self->baseline[i] = 0.9f * self->baseline[i] + 0.1f * self->img[i];
  capture_schedule (ssm, dev);
}

static void
capture_stop_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body, gsize len,
                 gpointer user_data)
{
  /* The stop opcode only acknowledges; its status word varies with the
   * capture state (e.g. 0x0412) and is not an error. */
  capture_decide (ssm, dev);
}

static void
capture_discard_stop_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body,
                         gsize len, gpointer user_data)
{
  /* Stop is an acknowledgement; its status word is not an error. */
  capture_schedule (ssm, dev);
}

static void
capture_raw_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                gpointer user_data, GError *error)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  FpiSsm *ssm = user_data;
  guint8 stop = 0x04;

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (s00a8_image_decode (transfer->buffer, transfer->actual_length, self->img) == 0)
    {
      s00a8_exchange (ssm, dev, "capture-discard-stop", &stop, 1,
                      capture_discard_stop_cb, NULL);
      return;
    }
  s00a8_exchange (ssm, dev, "capture-stop", &stop, 1, capture_stop_cb, NULL);
}

static void
capture_recover_done_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body,
                         gsize len, gpointer user_data)
{
  if (!command_status_ok (ssm, body, len, "capture recovery stop"))
    return;
  capture_send (ssm, dev);
}

static void
capture_recover_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                    gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  guint8 stop = 0x04;

  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  if (error == NULL && transfer->actual_length > 0 && self->drain_left-- > 0)
    {
      FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

      fpi_usb_transfer_fill_bulk (t, S00A8_EP_IMAGE_IN, 0x40000);
      t->short_is_error = FALSE;
      fpi_usb_transfer_submit (t, 300, fpi_device_get_cancellable (dev),
                               capture_recover_cb, ssm);
      return;
    }
  g_clear_error (&error);
  s00a8_exchange (ssm, dev, "capture-recover-stop", &stop, 1,
                  capture_recover_done_cb, NULL);
}

static void
capture_cmd_cb (FpDevice *dev, FpiSsm *ssm, const guint8 *body, gsize len,
                gpointer user_data)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  guint16 status = status_of (body, len);
  FpiUsbTransfer *in;

  /* 0x0450: a capture from an aborted session is still streaming; drain
   * EP 0x82, stop it and retry. */
  if (status == 0x0450 && self->busy_retries++ < 3)
    {
      FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

      self->drain_left = 256;
      fpi_usb_transfer_fill_bulk (t, S00A8_EP_IMAGE_IN, 0x40000);
      t->short_is_error = FALSE;
      fpi_usb_transfer_submit (t, 300, fpi_device_get_cancellable (dev),
                               capture_recover_cb, ssm);
      return;
    }
  if (status != 0)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                           "capture command refused (0x%04x)", status));
      return;
    }
  self->busy_retries = 0;

  in = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (in, S00A8_EP_IMAGE_IN, CAPTURE_LINES * S00A8_LINE_STRIDE);
  in->short_is_error = FALSE;
  fpi_usb_transfer_submit (in, S00A8_TIMEOUT_MS, fpi_device_get_cancellable (dev),
                           capture_raw_cb, ssm);
}

static void
capture_send (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  const guint8 *cal;
  guint8 fallback[S00A8_FACTORY_CAL_LEN];
  g_autofree guint8 *cmd = NULL;
  gsize cmd_len = 0;

  if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
    {
      fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                     "cancelled"));
      return;
    }
  if (self->have_factory_cal)
    {
      cal = self->factory_cal;
    }
  else
    {
      memset (fallback, 0x80, sizeof (fallback));
      cal = fallback;
    }
  cmd = s00a8_capture_command (CAPTURE_LINES, cal,
                               self->have_cal ? self->cal_frame : NULL, &cmd_len);
  if (cmd == NULL)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                           "could not build capture command"));
      return;
    }
  s00a8_exchange (ssm, dev, "capture", cmd, cmd_len, capture_cmd_cb, NULL);
}

/* Allocate the capture working set and start the loop, jumping to
 * done_state once a finger template is ready. */
static void
capture_start (FpiSsm *ssm, FpDevice *dev, gint done_state)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  if (self->img == NULL)
    {
      self->img = g_new0 (gfloat, S00A8_PIXELS);
      self->baseline = g_new0 (gfloat, S00A8_PIXELS);
      self->previous = g_new0 (gfloat, S00A8_PIXELS);
      self->cal_frame = g_new0 (guint8, S00A8_PIXELS);
      self->template = g_new0 (gint8, S00A8_PIXELS);
    }
  if (!self->have_cal && !self->have_baseline)
    load_capture_reference (self, fpi_device_get_usb_device (dev));
  self->done_state = done_state;
  if (!self->await_lift)
    fpi_device_report_finger_status (dev,
        self->have_cal && self->have_baseline ? FP_FINGER_STATUS_NEEDED
                                              : FP_FINGER_STATUS_NONE);
  capture_send (ssm, dev);
}

/* ---- session prep as a sub-SSM ------------------------------------------ */

static void
prep_done_cb (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  if (error)
    fpi_ssm_mark_failed (self->task_ssm, error);
  else
    fpi_ssm_next_state (self->task_ssm);
}

static void
run_session_prep (FpDevice *dev)
{
  FpiSsm *prep = fpi_ssm_new (dev, prep_run_state, PREP_STATES);

  fpi_ssm_start (prep, prep_done_cb);
}

/* ---- template storage --------------------------------------------------- */

static void
store_templates (FpPrint *print, GByteArray *tpls, const gdouble *poses, guint n)
{
  GVariant *data = g_variant_new ("(uu@ay@ad)", PRINT_VERSION, n,
                                  g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                             tpls->data, tpls->len, 1),
                                  g_variant_new_fixed_array (G_VARIANT_TYPE_DOUBLE, poses,
                                                             (gsize) n * S00A8_POSE_LEN,
                                                             sizeof (gdouble)));
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
}

static S00a8Model *
load_model (FpPrint *print, GError **error)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) tpl_v = NULL;
  g_autoptr(GVariant) pose_v = NULL;
  const gint8 *tpls;
  const gdouble *poses;
  gsize tpl_len = 0, pose_len = 0;
  guint32 version = 0, count = 0;
  S00a8Model *model;

  g_object_get (print, "fpi-data", &data, NULL);
  if (data == NULL || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(uuayad)")))
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "print was not enrolled with this driver, please re-enroll");
      return NULL;
    }
  g_variant_get (data, "(uu@ay@ad)", &version, &count, &tpl_v, &pose_v);
  tpls = g_variant_get_fixed_array (tpl_v, &tpl_len, 1);
  poses = g_variant_get_fixed_array (pose_v, &pose_len, sizeof (gdouble));
  if (version != PRINT_VERSION || count == 0 || count > MAX_TEMPLATES ||
      tpl_len != (gsize) count * S00A8_PIXELS ||
      pose_len != (gsize) count * S00A8_POSE_LEN)
    {
      g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                           "unsupported print data, please re-enroll");
      return NULL;
    }
  model = s00a8_model_new (tpls, count, poses);
  if (model == NULL)
    g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                         "corrupt print data, please re-enroll");
  return model;
}

/* Identify must return the scanned print even if none of the enrolled
 * templates match, so libfprint can use it for duplicate detection. */
static FpPrint *
make_scanned_print (FpDevice *dev, const gint8 *tpl)
{
  g_autofree gdouble *poses = g_new (gdouble, S00A8_POSE_LEN);
  g_autoptr(GByteArray) templates = g_byte_array_new ();
  g_autoptr(S00a8Aligner) aligner = s00a8_aligner_new ();
  g_autoptr(S00a8Model) model = NULL;
  FpPrint *print = fp_print_new (dev);

  g_byte_array_append (templates, (const guint8 *) tpl, S00A8_PIXELS);
  s00a8_aligner_add (aligner, tpl);
  model = s00a8_aligner_finish (aligner, poses);
  if (model == NULL)
    {
      g_object_unref (print);
      return NULL;
    }
  store_templates (print, templates, poses, 1);
  return print;
}

/* ---- enrolment ---------------------------------------------------------- */

enum { ENROLL_PREP, ENROLL_CAPTURE, ENROLL_COMMIT, ENROLL_STATES_N };

static void
enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_PREP:
      run_session_prep (dev);
      break;

    case ENROLL_CAPTURE:
      capture_start (ssm, dev, ENROLL_COMMIT);
      break;

    case ENROLL_COMMIT:
      if (self->coverage < MIN_COVERAGE)
        {
          fpi_device_enroll_progress (dev, self->enroll_done, NULL,
              fpi_device_retry_new_msg (FP_DEVICE_RETRY_CENTER_FINGER,
                                        "Please place the finger flat and centred"));
          if (++self->enroll_tries > ENROLL_MAX_TRIES)
            {
              fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                   "too many unusable presses"));
              return;
            }
          fpi_ssm_jump_to_state (ssm, ENROLL_CAPTURE);
          return;
        }
      s00a8_aligner_add (self->aligner, self->template);
      g_byte_array_append (self->templates, (const guint8 *) self->template, S00A8_PIXELS);
      self->enroll_done++;
      fpi_device_enroll_progress (dev, self->enroll_done, NULL, NULL);

      if (self->enroll_done < ENROLL_STAGES)
        {
          fpi_ssm_jump_to_state (ssm, ENROLL_CAPTURE);
          return;
        }
      {
        FpPrint *print = NULL;
        guint n = self->templates->len / S00A8_PIXELS;
        g_autofree gdouble *poses = g_new (gdouble, (gsize) n * S00A8_POSE_LEN);
        g_autoptr(S00a8Model) model = s00a8_aligner_finish (self->aligner, poses);

        if (model == NULL)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
                FP_DEVICE_ERROR_DATA_INVALID, "could not render enrolled templates"));
            return;
          }
        fp_info ("enrolled %u templates in %u islands", n, s00a8_model_islands (model));
        fpi_device_get_enroll_data (dev, &print);
        store_templates (print, self->templates, poses, n);
      }
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
enroll_done_cb (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  FpPrint *print = NULL;

  self->task_ssm = NULL;
  g_clear_pointer (&self->aligner, s00a8_aligner_free);
  g_clear_pointer (&self->templates, g_byte_array_unref);

  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }
  fpi_device_get_enroll_data (dev, &print);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  self->enroll_done = 0;
  self->enroll_tries = 0;
  g_clear_pointer (&self->aligner, s00a8_aligner_free);
  g_clear_pointer (&self->templates, g_byte_array_unref);
  self->aligner = s00a8_aligner_new ();
  self->templates = g_byte_array_new ();

  self->task_ssm = fpi_ssm_new (dev, enroll_run_state, ENROLL_STATES_N);
  fpi_ssm_start (self->task_ssm, enroll_done_cb);
}

/* ---- verification ------------------------------------------------------- */

enum { VERIFY_PREP, VERIFY_CAPTURE, VERIFY_MATCH, VERIFY_STATES_N };

static void
verify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIFY_PREP:
      run_session_prep (dev);
      break;

    case VERIFY_CAPTURE:
      capture_start (ssm, dev, VERIFY_MATCH);
      break;

    case VERIFY_MATCH:
      {
        g_autoptr(GError) error = NULL;
        FpPrint *enrolled = NULL;
        gdouble score, self_score, norm;

        if (self->coverage < MIN_COVERAGE)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_retry_new_msg (
                FP_DEVICE_RETRY_CENTER_FINGER,
                "Please place the finger flat and centred"));
            return;
          }

        if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_IDENTIFY)
          {
            GPtrArray *prints = NULL;

            fpi_device_get_identify_data (dev, &prints);
            self->verify_result = FPI_MATCH_FAIL;
            for (guint i = 0; i < prints->len; i++)
              {
                g_autoptr(S00a8Model) model = NULL;

                if (g_cancellable_set_error_if_cancelled (
                        fpi_device_get_cancellable (dev), &error))
                  {
                    self->verify_result = FPI_MATCH_ERROR;
                    break;
                  }
                enrolled = g_ptr_array_index (prints, i);
                model = load_model (enrolled, &error);
                if (model == NULL)
                  {
                    self->verify_result = FPI_MATCH_ERROR;
                    break;
                  }
                score = s00a8_model_score (model, self->template);
                self_score = s00a8_match_self_score (self->template);
                norm = (score - self_score) / MAX (1 - self_score, 1e-3);
                self->verify_result = (score >= MATCH_THRESHOLD && norm >= NORM_THRESHOLD)
                                      ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;
                fp_info ("identify score %.3f self %.3f norm %.3f -> %s",
                         score, self_score, norm,
                         self->verify_result == FPI_MATCH_SUCCESS ? "match" : "no match");
                if (self->verify_result == FPI_MATCH_SUCCESS)
                  {
                    self->identify_match = enrolled;
                    break;
                  }
              }
            if (self->verify_result == FPI_MATCH_ERROR)
              {
                fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
                return;
              }
          }
        else
          {
            g_autoptr(S00a8Model) model = NULL;

            fpi_device_get_verify_data (dev, &enrolled);
            model = load_model (enrolled, &error);
            if (model == NULL)
              {
                fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
                return;
              }
            score = s00a8_model_score (model, self->template);
            self_score = s00a8_match_self_score (self->template);
            norm = (score - self_score) / MAX (1 - self_score, 1e-3);
            self->verify_result = (score >= MATCH_THRESHOLD && norm >= NORM_THRESHOLD)
                                  ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;
            fp_info ("verify score %.3f self %.3f norm %.3f -> %s",
                     score, self_score, norm,
                     self->verify_result == FPI_MATCH_SUCCESS ? "match" : "no match");
          }
        fpi_ssm_next_state (ssm);
        break;
      }
    }
}

static void
verify_done_cb (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  self->task_ssm = NULL;

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_IDENTIFY)
    {
      if (error && error->domain == FP_DEVICE_RETRY)
        {
          fpi_device_identify_report (dev, NULL, NULL, error);
          error = NULL;
        }
      else if (!error)
        {
          g_autoptr(FpPrint) scanned = make_scanned_print (dev, self->template);
          if (scanned == NULL)
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                               "could not create scanned print");
          else
            fpi_device_identify_report (dev, self->identify_match,
                                        g_steal_pointer (&scanned), NULL);
        }
      self->identify_match = NULL;
      fpi_device_identify_complete (dev, error);
      return;
    }

  if (error)
    {
      if (error->domain == FP_DEVICE_RETRY)
        fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, error);
      else
        {
          fpi_device_verify_complete (dev, error);
          return;
        }
    }
  else
    {
      fpi_device_verify_report (dev, self->verify_result, NULL, NULL);
    }
  fpi_device_verify_complete (dev, NULL);
}

static void
dev_verify (FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  self->verify_result = FPI_MATCH_ERROR;
  self->task_ssm = fpi_ssm_new (dev, verify_run_state, VERIFY_STATES_N);
  fpi_ssm_start (self->task_ssm, verify_done_cb);
}

static void
dev_identify (FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);

  self->verify_result = FPI_MATCH_ERROR;
  self->identify_match = NULL;
  self->task_ssm = fpi_ssm_new (dev, verify_run_state, VERIFY_STATES_N);
  fpi_ssm_start (self->task_ssm, verify_done_cb);
}

/* ---- open / close ------------------------------------------------------- */

/* Drop any leftover bytes an aborted earlier session left on the command
 * and image endpoints, so the next read sees only fresh data. */
static void
drain_endpoints (GUsbDevice *usb, GCancellable *cancellable)
{
  const guint8 eps[] = { S00A8_EP_CMD_IN, S00A8_EP_IMAGE_IN };
  g_autofree guint8 *buf = g_malloc (0x20000);

  for (guint i = 0; i < G_N_ELEMENTS (eps); i++)
    for (guint n = 0; n < 64; n++)
      {
        gsize got = 0;

        if (cancellable && g_cancellable_is_cancelled (cancellable))
          return;
        if (!g_usb_device_bulk_transfer (usb, eps[i], buf, 0x20000, &got, 60,
                                         NULL, NULL) ||
            got == 0)
          break;
      }
}

/* Plaintext setup the sensor expects before the TLS handshake. */
static gboolean
plaintext_init (GUsbDevice *usb, GCancellable *cancellable, GError **error)
{
  g_autofree guint8 *msg4 = g_malloc (1 + VALIDITY_INIT_MSG4_PAYLOAD_LEN);
  g_autofree guint8 *buf = g_malloc (S00A8_MAX_RESPONSE);
  const guint8 cmd_5b = 0x5b, cmd_rom = 0x01, cmd_msg2 = 0x19;
  const guint8 fw_probe[2] = { 0x43, 0x02 };
  gsize len = 0;

  msg4[0] = 0x06;
  memcpy (msg4 + 1, validity_init_msg4_payload, VALIDITY_INIT_MSG4_PAYLOAD_LEN);

  if (!s00a8_plain_command (usb, cancellable, msg4,
                            1 + VALIDITY_INIT_MSG4_PAYLOAD_LEN, error) ||
      !s00a8_plain_command (usb, cancellable, &cmd_5b, 1, error) ||
      !s00a8_plain_command (usb, cancellable, &cmd_rom, 1, error) ||
      !s00a8_plain_command (usb, cancellable, &cmd_msg2, 1, error))
    return FALSE;

  /* Diagnostic firmware probe; the reply is not needed. */
  s00a8_usb_exchange (usb, cancellable, fw_probe, sizeof (fw_probe),
                      buf, S00A8_MAX_RESPONSE, &len, NULL);
  return TRUE;
}

static void
dev_open_thread (GTask *task, gpointer source_object, gpointer task_data,
                 GCancellable *cancellable)
{
  FpDevice *dev = FP_DEVICE (source_object);
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  GUsbDevice *usb = G_USB_DEVICE (task_data);
  g_autoptr(GError) error = NULL;
  gboolean pairing_loaded;
  gboolean pairing_state_exists = FALSE;
  gboolean claimed = FALSE;

  if (!g_usb_device_claim_interface (usb, 0, 0, &error))
    goto out;
  claimed = TRUE;
  if (!s00a8_device_state_init (usb, &error))
    goto out;

  /* Clear command/image data left by a process that exited during pairing,
   * before the next command can consume a stale response. */
  drain_endpoints (usb, cancellable);
  if (cancellable && g_cancellable_is_cancelled (cancellable))
    {
      g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                           "open cancelled");
      goto out;
    }

  pairing_loaded = s00a8_pairing_load (usb, &self->pairing,
                                       &pairing_state_exists, &error);
  if (!pairing_loaded)
    {
      if (pairing_state_exists)
        goto out;
      g_clear_error (&error);
      if (!s00a8_pairing_create (usb, cancellable, &self->pairing, &error))
        goto out;
      remove_saved_baseline (usb);
    }

  drain_endpoints (usb, cancellable);
  if (cancellable && g_cancellable_is_cancelled (cancellable))
    {
      g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "open cancelled");
      goto out;
    }
  if (!plaintext_init (usb, cancellable, &error))
    {
      if (cancellable && g_cancellable_is_cancelled (cancellable))
        goto out;
      /* A sensor left mid-transfer by a killed process stalls here; a USB
       * reset brings it back without disturbing the pairing. */
      fp_info ("plaintext init failed (%s); resetting the sensor", error->message);
      g_clear_error (&error);
      if (!g_usb_device_reset (usb, &error))
        goto out;
      claimed = FALSE;
      if (!g_usb_device_claim_interface (usb, 0, 0, &error))
        goto out;
      claimed = TRUE;
      drain_endpoints (usb, cancellable);
      if (!plaintext_init (usb, cancellable, &error))
        goto out;
    }

  if (!s00a8_tls_handshake (usb, cancellable, &self->tls,
                            &self->pairing, &error))
    {
      if (self->pairing.pending && s00a8_tls_is_unpaired_error (error))
        {
          g_autoptr(GError) cleanup_error = NULL;

          if (!s00a8_pairing_remove_saved (usb, &cleanup_error))
            {
              s00a8_pairing_clear (&self->pairing);
              g_clear_error (&error);
              error = g_steal_pointer (&cleanup_error);
              goto out;
            }
          s00a8_pairing_clear (&self->pairing);
          g_clear_error (&error);
          error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                            "interrupted pairing was discarded; retry opening the device");
        }
      else if (pairing_loaded && s00a8_tls_is_unpaired_error (error))
        {
          g_clear_error (&error);
          error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                            "sensor does not match the stored pairing; remove the saved pairing to pair explicitly");
        }
      goto out;
    }

  if (self->pairing.pending)
    {
      g_autoptr(GError) marker_error = NULL;

      if (!s00a8_pairing_commit_pending (usb, &self->pairing, &marker_error))
        fp_warn ("cannot remove committed pairing marker: %s", marker_error->message);
    }

  if (cancellable && g_cancellable_is_cancelled (cancellable))
    {
      s00a8_tls_clear (&self->tls);
      g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "open cancelled");
      goto out;
    }
  g_task_return_boolean (task, TRUE);
  return;

out:
  if (claimed)
    g_usb_device_release_interface (usb, 0, 0, NULL);
  if (error == NULL)
    error = fpi_device_error_new (FP_DEVICE_ERROR_GENERAL);
  g_task_return_error (task, g_steal_pointer (&error));
}

static void
dev_open_done (GObject *source_object, GAsyncResult *result, gpointer user_data)
{
  g_autoptr(GError) error = NULL;

  g_task_propagate_boolean (G_TASK (result), &error);
  fpi_device_open_complete (FP_DEVICE (source_object), g_steal_pointer (&error));
}

static void
dev_open (FpDevice *dev)
{
  g_autoptr(GTask) task = g_task_new (dev, fpi_device_get_cancellable (dev),
                                      dev_open_done, NULL);

  g_task_set_check_cancellable (task, FALSE);
  g_task_set_task_data (task, g_object_ref (fpi_device_get_usb_device (dev)), g_object_unref);
  g_task_run_in_thread (task, dev_open_thread);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (dev);
  g_autoptr(GError) error = NULL;

  s00a8_tls_clear (&self->tls);
  self->have_cal = FALSE;
  self->have_baseline = FALSE;
  self->have_previous = FALSE;
  self->await_lift = FALSE;
  self->stable = 0;
  self->busy_retries = 0;
  self->drain_left = 0;
  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  fpi_device_close_complete (dev, g_steal_pointer (&error));
}

static void
dev_probe (FpDevice *dev)
{
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  g_autofree gchar *serial = NULL;
  g_autoptr(GError) error = NULL;

  if (!g_usb_device_open (usb, &error))
    {
      fpi_device_probe_complete (dev, NULL, NULL, g_steal_pointer (&error));
      return;
    }
  serial = g_usb_device_get_string_descriptor (usb,
              g_usb_device_get_serial_number_index (usb), NULL);
  g_usb_device_close (usb, NULL);
  fpi_device_probe_complete (dev, serial ? serial : "unknown", NULL, NULL);
}

/* ---- GObject ------------------------------------------------------------ */

static void
fpi_device_synaptics00a8_init (FpiDeviceSynaptics00a8 *self)
{
}

static void
dev_finalize (GObject *object)
{
  FpiDeviceSynaptics00a8 *self = FPI_DEVICE_SYNAPTICS00A8 (object);

  s00a8_tls_clear (&self->tls);
  s00a8_pairing_clear (&self->pairing);
  g_clear_pointer (&self->img, g_free);
  g_clear_pointer (&self->baseline, g_free);
  g_clear_pointer (&self->previous, g_free);
  g_clear_pointer (&self->cal_frame, g_free);
  g_clear_pointer (&self->template, g_free);
  g_clear_pointer (&self->aligner, s00a8_aligner_free);
  g_clear_pointer (&self->templates, g_byte_array_unref);
  G_OBJECT_CLASS (fpi_device_synaptics00a8_parent_class)->finalize (object);
}

static void
fpi_device_synaptics00a8_class_init (FpiDeviceSynaptics00a8Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  object_class->finalize = dev_finalize;

  dev_class->id = "synaptics00a8";
  dev_class->full_name = "Synaptics 06cb:00a8 fingerprint reader";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;
  dev_class->features = FP_DEVICE_FEATURE_VERIFY |
                        FP_DEVICE_FEATURE_IDENTIFY |
                        FP_DEVICE_FEATURE_ALWAYS_ON;

  dev_class->probe = dev_probe;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;
}

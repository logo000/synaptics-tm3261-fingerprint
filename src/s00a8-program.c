/*
 * Synaptics 06cb:00a8 - capture command
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
 * Command 0x02 loads and runs a capture program: a 5 byte header (bytes
 * per line, number of lines to deliver) followed by typed chunks
 * (u16 type, u16 length, data). The base program in s00a8-program-data.c
 * carries the register setup and the timeslot table that drives the scan.
 * This file assembles the per-capture command around it:
 *
 *  - the timeslot table is patched so every image row is sampled twice;
 *  - "line update" entries change values per image row while the scan
 *    runs: the receive electrode of the row, two analog trim registers
 *    loaded from the sensor's factory calibration, and, once a
 *    finger-free calibration frame exists, an offset correction per group
 *    of four columns.
 *
 * Chunk and instruction names follow python-validity (timeslot.py).
 */

#define FP_COMPONENT "synaptics00a8"

#include "drivers_api.h"
#include "s00a8.h"

#define CH_TIMESLOT       0x34
#define CH_REPLY_CONFIG   0x17
#define CH_LINE_TABLE     0x30
#define CH_LINE_DATA      0x43
#define CH_LINE_REPEAT    0x44

#define MAX_LINES         48
#define BYTES_PER_LINE    160
#define CAL_COLS          144
#define CAL_ROWS          56
#define GROUP             4

#define OP_ENABLE_RX      6
#define OP_REG_WRITE      13

#define REG_TRIM_A        0x8000203cu
#define REG_TRIM_B        0x80002040u

#define LU_SEQ(n)         ((guint32) (n) << 20)
#define LU_ACTIVE         0x07000000u
#define LU_WORD           0x40000000u
#define LU_TYPE           0x10000000u
#define LU_OFFSET_CAL     0x85000000u

typedef struct
{
  guint32  mask;
  guint32  flags;
  guint8   tag[4];
  guint8  *data;
  gsize    len;
} Line;

static void
put_u16 (GByteArray *out, guint v)
{
  guint8 b[2] = { v & 0xff, (v >> 8) & 0xff };

  g_byte_array_append (out, b, sizeof (b));
}

static void
put_u32 (GByteArray *out, guint32 v)
{
  guint8 b[4] = { v, v >> 8, v >> 16, v >> 24 };

  g_byte_array_append (out, b, sizeof (b));
}

/* Length of one timeslot instruction and its class, mirroring
 * python-validity's decode_insn. *reg is the register address for a
 * register-write instruction, else 0. Returns 0 on an unknown byte. */
static gsize
ts_insn (const guint8 *b, gsize avail, guint *op, guint32 *reg)
{
  guint8 c = b[0];

  *op = 0;
  *reg = 0;
  if (avail == 0)
    return 0;
  if (c <= 4)                     { *op = c;  return 1; }
  if (c >= 5 && c <= 7)           { *op = c;  return 2; }
  if ((c & 0xfe) == 0x08)         { *op = 8;  return 2; }
  if ((c & 0xfe) == 0x0a)         { *op = 9;  return 2; }
  if ((c & 0xfc) == 0x0c)         { *op = 10; return 1; }
  if ((c & 0xf8) == 0x10)         { *op = 11; return 3; }
  if ((c & 0xe0) == 0x20)         { *op = 12; return 1; }
  if ((c & 0xc0) == 0x40)
    {
      *op = OP_REG_WRITE;
      *reg = (guint32) (c & 0x3f) * 4 + 0x80002000u;
      return 3;
    }
  if ((c & 0xc0) == 0x80)         { *op = 14; return 1; }
  return 2;                       /* (c & 0xc0) == 0xc0 */
}

/* Program counter of the n-th instruction of class op, or the n-th write
 * to register reg when reg is non-zero. Returns -1 if not found. */
static gssize
ts_find (const guint8 *ts, gsize len, guint op, guint32 reg, guint n)
{
  for (gsize pc = 0; pc < len;)
    {
      guint cur_op;
      guint32 cur_reg;
      gsize sz = ts_insn (ts + pc, len - pc, &cur_op, &cur_reg);

      if (sz == 0 || sz > len - pc)
        return -1;
      if (reg ? (cur_op == OP_REG_WRITE && cur_reg == reg) : (cur_op == op))
        if (--n == 0)
          return (gssize) pc;
      pc += sz;
    }
  return -1;
}

/* Double every "lines per sweep" count so each row is sampled twice, and
 * advance the paired row address (python-validity patch_timeslot_table). */
static void
ts_double_rows (guint8 *ts, gsize len)
{
  for (gsize i = 0; i + 3 < len;)
    {
      if ((ts[i] & 0xf8) == 0x10)
        {
          if (ts[i + 2] > 1)
            {
              ts[i + 2] *= S00A8_LINE_REPEAT;
              ts[i + 1] += 1;
            }
          i += 3;
        }
      else if (ts[i] == 0)
        i += 1;
      else if (ts[i] == 7)
        i += 2;
      else
        break;
    }
}

/* Pack samples as bit-width offsets from their minimum, LSB first. */
static guint8 *
pack_samples (const guint8 *data, gsize len, guint8 *bits_out,
              guint8 *base_out, gsize *out_len)
{
  guint8 lo = 0xff, hi = 0;
  guint bits = 0;
  guint8 *out;

  for (gsize i = 0; i < len; i++)
    {
      lo = MIN (lo, data[i]);
      hi = MAX (hi, data[i]);
    }
  for (guint v = hi - lo; v; v >>= 1)
    bits++;
  *bits_out = bits;
  *base_out = lo;
  if (bits == 0)
    {
      /* The line-update encoding has no representation for a zero-bit
       * sample width: the tag stores width - 1.  Encode a constant stream
       * as one-bit zero offsets instead, so the decoder sees a valid width
       * and the advertised inline length has matching data. */
      *bits_out = 1;
      *out_len = (len + 7) / 8;
      return g_malloc0 (*out_len + 1);
    }

  *out_len = (bits * len + 7) / 8;
  out = g_malloc0 (*out_len + 1);
  for (gsize i = 0; i < len; i++)
    {
      guint val = data[i] - lo;
      gsize off = i * bits;

      out[off / 8] |= (guint8) (val << (off % 8));
      out[off / 8 + 1] |= (guint8) (val >> (8 - off % 8));
    }
  return out;
}

/* Build a command 0x02 payload that captures `lines` lines. factory_cal
 * has S00A8_FACTORY_CAL_LEN values; blank is a finger-free calibration
 * frame (S00A8_PIXELS bytes) or NULL before one exists. */
guint8 *
s00a8_capture_command (guint16 lines, const guint8 *factory_cal,
                       const guint8 *blank, gsize *out_len)
{
  const guint8 *prog = validity_capture33_prog_2449_6_20;
  gsize prog_len = sizeof (validity_capture33_prog_2449_6_20);
  g_autoptr(GByteArray) out = g_byte_array_new ();
  Line lines_tbl[MAX_LINES];
  guint n_lines = 0;
  guint seq = 2;
  guint8 *ts = NULL;
  gsize ts_len = 0;
  gsize pos = 0;
  gssize ts_off = -1;
  guint8 hdr[5] = { 0x02, BYTES_PER_LINE & 0xff, BYTES_PER_LINE >> 8,
                    lines & 0xff, lines >> 8 };

  g_byte_array_append (out, hdr, sizeof (hdr));

  /* Copy the base program chunk by chunk; patch the timeslot table so
   * each row is sampled twice. */
  while (pos + 4 <= prog_len)
    {
      guint type = prog[pos] | (prog[pos + 1] << 8);
      guint len = prog[pos + 2] | (prog[pos + 3] << 8);
      gsize start;

      if (pos + 4 + len > prog_len)
        break;
      put_u16 (out, type);
      put_u16 (out, len);
      start = out->len;
      g_byte_array_append (out, prog + pos + 4, len);
      if (type == CH_TIMESLOT)
        {
          ts_off = start;
          ts_len = len;
          ts_double_rows (out->data + start, ts_len);
        }
      pos += 4 + len;
    }
  if (ts_off < 0)
    return NULL;   /* out is freed by g_autoptr */
  ts = out->data + ts_off;

  /* Line updates that patch registers per row, anchored at instructions
   * of the timeslot table. The lookups run before any further append so
   * the timeslot pointer stays valid. */
  {
    gssize rx2 = ts_find (ts, ts_len, OP_ENABLE_RX, 0, 2);
    gssize trim_a = ts_find (ts, ts_len, 0, REG_TRIM_A, 1);
    gssize trim_b = ts_find (ts, ts_len, 0, REG_TRIM_B, 1);
    gssize rx3 = ts_find (ts, ts_len, OP_ENABLE_RX, 0, 3);
    gssize rx4 = ts_find (ts, ts_len, OP_ENABLE_RX, 0, 4);

    if (rx2 >= 0)
      {
        Line *l = &lines_tbl[n_lines++];
        l->mask = 0xff;
        l->flags = LU_SEQ (seq++) | LU_ACTIVE | (guint32) (rx2 + 1);
        l->len = sizeof (validity_capture33_calib_2449);
        l->data = g_memdup2 (validity_capture33_calib_2449, l->len);
        l->tag[0] = 0x0f;
        l->tag[1] = l->tag[2] = l->tag[3] = 0;
      }

    for (guint k = 0; k < 2; k++)
      {
        gssize pc = k == 0 ? trim_a : trim_b;
        guint8 bits, base;
        Line *l;

        if (pc < 0)
          continue;
        l = &lines_tbl[n_lines++];
        l->mask = 0xff;
        l->flags = LU_SEQ (seq++) | LU_ACTIVE | (guint32) (pc + 1);
        l->data = pack_samples (factory_cal, S00A8_FACTORY_CAL_LEN, &bits, &base,
                                &l->len);
        l->tag[0] = (guint8) (((bits - 1) & 0xff) | 8);
        l->tag[1] = base;
        l->tag[2] = l->tag[3] = 0;
      }

    for (guint k = 0; k < 2; k++)
      {
        gssize pc = k == 0 ? rx3 : rx4;
        Line *l;

        if (pc < 0)
          continue;
        l = &lines_tbl[n_lines++];
        l->mask = 0xffff;
        l->flags = LU_SEQ (seq++) | LU_WORD | LU_ACTIVE | (guint32) pc;
        l->data = NULL;
        l->len = 0;
        memset (l->tag, 0, sizeof (l->tag));
      }

    {
      Line *l = &lines_tbl[n_lines++];
      l->mask = 0xff;
      l->flags = LU_SEQ (seq++) | LU_TYPE | LU_ACTIVE | 0x374u;
      l->data = NULL;
      l->len = 0;
      l->tag[0] = 0;
      l->tag[1] = 0x0c;
      l->tag[2] = l->tag[3] = 0;
    }

    /* Per-group offset correction from the calibration frame: one line
     * per group of four columns, 56 rows x 4 values of (v - 0x80)*10/4. */
    if (blank != NULL)
      for (guint col = 0; col + GROUP <= CAL_COLS; col += GROUP)
        {
          Line *l = &lines_tbl[n_lines++];

          l->mask = 0xffffffffu;
          l->flags = LU_OFFSET_CAL | col;
          l->len = CAL_ROWS * GROUP;
          l->data = g_malloc (l->len);
          memset (l->tag, 0, sizeof (l->tag));
          for (guint r = 0; r < CAL_ROWS; r++)
            for (guint j = 0; j < GROUP; j++)
              {
                gint v = ((gint) blank[r * CAL_COLS + col + j] - 0x80) * 10 / 4;
                l->data[r * GROUP + j] = (guint8) (gint8) CLAMP (v, -128, 127);
              }
        }
  }

  /* Empty reply-config chunk. */
  put_u16 (out, CH_REPLY_CONFIG);
  put_u16 (out, 0);

  /* Repeat each frame S00A8_LINE_REPEAT times. */
  put_u16 (out, CH_LINE_REPEAT);
  put_u16 (out, 4);
  put_u32 (out, S00A8_LINE_REPEAT - 1);

  /* Line table: header plus the inline data of the low-sequence lines. */
  {
    gsize inline_len = 0;

    for (guint i = 0; i < n_lines; i++)
      if (((lines_tbl[i].flags >> 20) & 0xf) <= 1)
        inline_len += (lines_tbl[i].len + 3) / 4 * 4;
    put_u16 (out, CH_LINE_TABLE);
    put_u16 (out, 4 + 8 * n_lines + inline_len);
    put_u32 (out, n_lines);
    for (guint i = 0; i < n_lines; i++)
      {
        put_u32 (out, lines_tbl[i].mask);
        put_u32 (out, lines_tbl[i].flags);
      }
    for (guint i = 0; i < n_lines; i++)
      if (((lines_tbl[i].flags >> 20) & 0xf) <= 1 && lines_tbl[i].len)
        {
          static const guint8 zero[4] = { 0 };

          g_byte_array_append (out, lines_tbl[i].data, lines_tbl[i].len);
          g_byte_array_append (out, zero, (4 - lines_tbl[i].len % 4) % 4);
        }
  }

  /* Line data: the higher-sequence lines, each a 4 byte tag then its data
   * without padding; only the chunk end is aligned. */
  {
    gsize sum = 0;
    guint n_hi = 0;

    for (guint i = 0; i < n_lines; i++)
      if (((lines_tbl[i].flags >> 20) & 0xf) > 1)
        {
          n_hi++;
          sum += lines_tbl[i].len;
        }
    if (n_hi > 0)
      {
        static const guint8 zero[4] = { 0 };

        put_u16 (out, CH_LINE_DATA);
        put_u16 (out, n_hi * 4 + (sum + 3) / 4 * 4);
        for (guint i = 0; i < n_lines; i++)
          {
            if (((lines_tbl[i].flags >> 20) & 0xf) <= 1)
              continue;
            g_byte_array_append (out, lines_tbl[i].tag, 4);
            if (lines_tbl[i].len)
              g_byte_array_append (out, lines_tbl[i].data, lines_tbl[i].len);
          }
        g_byte_array_append (out, zero, (4 - sum % 4) % 4);
      }
  }

  for (guint i = 0; i < n_lines; i++)
    g_free (lines_tbl[i].data);

  /* The device rejects a command whose length is a multiple of 64. */
  if (out->len % 0x40 == 0)
    put_u32 (out, 0);

  *out_len = out->len;
  return g_byte_array_free (g_steal_pointer (&out), FALSE);
}

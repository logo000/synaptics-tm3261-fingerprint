/*
 * Synaptics 06cb:00a8 - frame decoding
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
 * EP 0x82 streams lines of 8 header bytes (01 fe <u16 counter> ...) and
 * 144 samples. The counter increases by one within a frame and jumps
 * between frames; each image row is sampled on two consecutive lines, so
 * a frame is 2 * 56 lines and several frames are temporal repeats that we
 * average for signal to noise.
 *
 * The 144 samples are not pixels. Each block of 16 is a code-division
 * measurement: with B = J - 2I (16x16, B*B = 16I) the 16 pixels of a
 * block are (B (x) B) applied to the 16 samples, then scaled back by
 * 1/4. s00a8_image_demux does that against a baseline; the raw samples
 * are what presence detection and the calibration frame work on.
 */

#define FP_COMPONENT "synaptics00a8"

#include "drivers_api.h"
#include "s00a8.h"

#include <math.h>

#define CDM_BLOCK   16

guint
s00a8_image_decode (const guint8 *raw, gsize raw_len, gfloat *out)
{
  gsize n_lines = raw_len / S00A8_LINE_STRIDE;
  g_autofree gdouble *acc = g_new0 (gdouble, S00A8_PIXELS);
  guint frames = 0;
  gsize i = 0;

  while (i < n_lines)
    {
      const guint8 *l = raw + i * S00A8_LINE_STRIDE;
      guint counter;
      gsize run = 1;

      if (l[0] != 0x01 || l[1] != 0xfe)
        {
          i++;
          continue;
        }
      counter = l[2] | (l[3] << 8);
      while (i + run < n_lines)
        {
          const guint8 *n = raw + (i + run) * S00A8_LINE_STRIDE;

          if (n[0] != 0x01 || n[1] != 0xfe ||
              (guint16) (n[2] | (n[3] << 8)) != (guint16) (counter + run))
            break;
          run++;
        }

      if (run >= S00A8_LINES_PER_FRAME)
        {
          for (guint y = 0; y < S00A8_HEIGHT; y++)
            {
              const guint8 *a = raw + (i + 2 * y) * S00A8_LINE_STRIDE + S00A8_LINE_HEADER;
              const guint8 *b = a + S00A8_LINE_STRIDE;

              for (guint x = 0; x < S00A8_WIDTH; x++)
                acc[y * S00A8_WIDTH + x] += (a[x] + b[x]) / 2.0;
            }
          frames++;
        }
      i += run;
    }

  if (frames == 0)
    return 0;
  for (guint p = 0; p < S00A8_PIXELS; p++)
    out[p] = (gfloat) (acc[p] / frames);
  return frames;
}

void
s00a8_image_demux (const gfloat *img, const gfloat *base, gfloat *out)
{
  for (guint y = 0; y < S00A8_HEIGHT; y++)
    for (guint blk = 0; blk < S00A8_WIDTH; blk += CDM_BLOCK)
      {
        gfloat x[CDM_BLOCK], grp[4] = { 0 }, sub[4] = { 0 }, total = 0;
        guint o = y * S00A8_WIDTH + blk;

        for (guint k = 0; k < CDM_BLOCK; k++)
          {
            x[k] = img[o + k] - (base ? base[o + k] : 0);
            grp[k / 4] += x[k];
            sub[k % 4] += x[k];
            total += x[k];
          }
        /* sum_hj B[g,h] B[i,j] x_hj with B = J - 2I expands to
         * total - 2 grp[g] - 2 sub[i] + 4 x_gi. */
        for (guint k = 0; k < CDM_BLOCK; k++)
          out[o + k] = (total - 2 * grp[k / 4] - 2 * sub[k % 4] + 4 * x[k]) / 4;
      }
}

gdouble
s00a8_image_difference (const gfloat *a, const gfloat *b)
{
  gdouble sum = 0;

  for (guint p = 0; p < S00A8_PIXELS; p++)
    sum += fabs (a[p] - b[p]);
  return sum / S00A8_PIXELS;
}

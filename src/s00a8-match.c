/*
 * Synaptics 06cb:00a8 - host-side matcher
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
 * The sensor sees about 7 x 3 mm, so two presses of the same finger share
 * only part of their area and minutiae matchers find too few common
 * points. This matcher compares ridge images directly and, at enrolment,
 * stitches the enrolled presses into a mosaic of the finger:
 *
 *  1. prepare: band-pass the decoded image, divide by the local ridge
 *     energy and mask the areas without ridge contrast. The unmasked
 *     fraction is the coverage used to reject partial presses.
 *  2. correlate: normalized cross correlation over the shared mask,
 *     evaluated for all translations at once with FFTs and for rotations
 *     of -20..20 degrees, over translations with enough overlap.
 *  3. model (enrolment): align every pair of templates and lay them out
 *     with a maximum spanning forest into mosaic islands.
 *  4. score (verification): best correlation of the probe against any
 *     island, minus its self similarity so that a merely regular ridge
 *     pattern from another finger cannot pass. The driver combines the
 *     two into the accept decision.
 */
#define FP_COMPONENT "synaptics00a8"

#include "drivers_api.h"
#include "s00a8.h"

#include <math.h>
#include <string.h>

#define W   S00A8_WIDTH
#define H   S00A8_HEIGHT
#define N   S00A8_PIXELS

#define MIN_OVERLAP   2000.0f
/* Pairs use a 128 x 256 FFT: shifts of +-(112..143) columns alias onto
 * each other, but their overlaps add up to at most 32 x 56 = 1792 pixels,
 * so a minimum of 1800 only admits unaliased translations. */
#define PAIR_OVERLAP  1800.0f
#define LINK_SCORE    0.75
#define ROT_MAX       20
#define ROT_STEP      2
#define N_ROTS        (2 * ROT_MAX / ROT_STEP + 1)
#define Z_SCALE       40.0f   /* int8 storage of the normalized ridge image */

/* Island canvas. Each island is cropped to its bounding box and gets an
 * FFT of at least (h + H - 1) x (w + W - 1), so the linear correlation
 * against a 56 x 144 probe never wraps. */
#define CH  200
#define CW  368
#define PAIR_FH  128
#define PAIR_FW  256
/* Upper bound on distinct FFT sizes across islands: heights pow2 of up to
 * CH + H and widths of up to CW + W give at most nine combinations. */
#define MAX_PLANS 16
#define REFINE_TOP 3
#define SELF_EXCLUDE 4
#define SELF_ROT_STEP 4
#define MAX_POSE_MATRIX 2.0
#define MAX_POSE_OFFSET 4096.0

typedef struct { gfloat re, im; } cpx;

/* ---- preprocessing ---------------------------------------------------- */

/* Separable Gaussian, scipy.ndimage semantics (truncate 4, mode reflect). */
static void
gauss (const gfloat *in, gfloat *out, gfloat sigma)
{
  gint r = (gint) (4.0f * sigma + 0.5f);
  g_autofree gfloat *k = g_new (gfloat, 2 * r + 1);
  g_autofree gfloat *tmp = g_new (gfloat, N);
  gfloat sum = 0;

  for (gint i = -r; i <= r; i++)
    sum += k[i + r] = expf (-0.5f * i * i / (sigma * sigma));
  for (gint i = 0; i <= 2 * r; i++)
    k[i] /= sum;

#define REFLECT(i, n) ((i) < 0 ? -(i) - 1 : (i) >= (n) ? 2 * (n) - (i) - 1 : (i))
  for (gint y = 0; y < H; y++)
    for (gint x = 0; x < W; x++)
      {
        gfloat s = 0;
        for (gint i = -r; i <= r; i++)
          {
            gint xx = x + i;
            while (xx < 0 || xx >= W)
              xx = REFLECT (xx, W);
            s += k[i + r] * in[y * W + xx];
          }
        tmp[y * W + x] = s;
      }
  for (gint y = 0; y < H; y++)
    for (gint x = 0; x < W; x++)
      {
        gfloat s = 0;
        for (gint i = -r; i <= r; i++)
          {
            gint yy = y + i;
            while (yy < 0 || yy >= H)
              yy = REFLECT (yy, H);
            s += k[i + r] * tmp[yy * W + x];
          }
        out[y * W + x] = s;
      }
#undef REFLECT
}

static int
cmp_float (const void *a, const void *b)
{
  gfloat x = *(const gfloat *) a, y = *(const gfloat *) b;

  return (x > y) - (x < y);
}

/* Normalized, masked ridge image as int8, -128 marking masked pixels.
 * Returns the coverage (fraction of unmasked pixels). */
gdouble
s00a8_match_prepare (const gfloat *px, gint8 *tpl)
{
  g_autofree gfloat *a = g_new (gfloat, N);
  g_autofree gfloat *g1 = g_new (gfloat, N);
  g_autofree gfloat *g2 = g_new (gfloat, N);
  g_autofree gfloat *col = g_new (gfloat, H);
  g_autofree guint8 *m = g_new (guint8, N);
  g_autofree guint8 *m2 = g_new (guint8, N);
  gfloat emax = 0, thr, pos;
  guint covered = 0;

  /* Remove the per-column offset left by the baseline. */
  for (gint x = 0; x < W; x++)
    {
      gfloat med;
      for (gint y = 0; y < H; y++)
        col[y] = px[y * W + x];
      qsort (col, H, sizeof (gfloat), cmp_float);
      med = (col[H / 2 - 1] + col[H / 2]) / 2;
      for (gint y = 0; y < H; y++)
        a[y * W + x] = px[y * W + x] - med;
    }

  gauss (a, g1, 0.8f);
  gauss (a, g2, 3.0f);
  for (gint p = 0; p < N; p++)
    {
      a[p] = g1[p] - g2[p];                /* band-passed ridge signal */
      g1[p] = a[p] * a[p];
    }
  gauss (g1, g2, 4.0f);
  for (gint p = 0; p < N; p++)
    {
      g2[p] = sqrtf (MAX (g2[p], 0));     /* local ridge energy */
      emax = MAX (emax, g2[p]);
    }

  memcpy (g1, g2, N * sizeof (gfloat));
  qsort (g1, N, sizeof (gfloat), cmp_float);
  pos = 0.98f * (N - 1);
  thr = g1[(gint) pos] + (pos - (gint) pos) * (g1[(gint) pos + 1] - g1[(gint) pos]);
  thr *= 0.35f;

  for (gint p = 0; p < N; p++)
    m[p] = g2[p] > thr;
  /* Three erosions with a 4-neighbourhood; outside counts as empty. */
  for (gint it = 0; it < 3; it++)
    {
      for (gint y = 0; y < H; y++)
        for (gint x = 0; x < W; x++)
          {
            gint p = y * W + x;
            m2[p] = m[p] &&
                    y > 0 && m[p - W] && y < H - 1 && m[p + W] &&
                    x > 0 && m[p - 1] && x < W - 1 && m[p + 1];
          }
      memcpy (m, m2, N);
    }

  for (gint p = 0; p < N; p++)
    {
      gfloat z = 0;
      if (m[p])
        {
          z = a[p] / (g2[p] + 1e-3f * emax);
          covered++;
        }
      tpl[p] = m[p] ? (gint8) CLAMP (lrintf (z * Z_SCALE), -127, 127) : -128;
    }
  return (gdouble) covered / N;
}

/* ---- FFT -------------------------------------------------------------- */

typedef struct
{
  gint  n, log2n;
  cpx  *tw;      /* e^{-2 pi i k / n}, k < n/2 */
  gint *rev;
} Fft1;

typedef struct
{
  gint  h, w;
  Fft1  rows, cols;
  cpx  *line;
} Fft2;

static void
fft1_init (Fft1 *f, gint n)
{
  f->n = n;
  for (f->log2n = 0; (1 << f->log2n) < n; f->log2n++)
    ;
  f->tw = g_new (cpx, n / 2);
  f->rev = g_new (gint, n);
  for (gint k = 0; k < n / 2; k++)
    f->tw[k] = (cpx) { cos (2 * G_PI * k / n), -sin (2 * G_PI * k / n) };
  for (gint i = 0; i < n; i++)
    {
      gint r = 0;
      for (gint b = 0; b < f->log2n; b++)
        r |= ((i >> b) & 1) << (f->log2n - 1 - b);
      f->rev[i] = r;
    }
}

static void
fft1_run (const Fft1 *f, cpx *d, gboolean inverse)
{
  gint n = f->n;

  for (gint i = 0; i < n; i++)
    if (i < f->rev[i])
      {
        cpx t = d[i]; d[i] = d[f->rev[i]]; d[f->rev[i]] = t;
      }
  for (gint len = 2, step = n / 2; len <= n; len <<= 1, step >>= 1)
    for (gint i = 0; i < n; i += len)
      for (gint k = 0; k < len / 2; k++)
        {
          cpx w = f->tw[k * step];
          cpx *u = &d[i + k], *v = &d[i + k + len / 2];
          gfloat wi = inverse ? -w.im : w.im;
          cpx t = { v->re * w.re - v->im * wi, v->re * wi + v->im * w.re };
          v->re = u->re - t.re; v->im = u->im - t.im;
          u->re += t.re; u->im += t.im;
        }
}

static Fft2 *
fft2_new (gint h, gint w)
{
  Fft2 *f = g_new0 (Fft2, 1);

  f->h = h; f->w = w;
  fft1_init (&f->rows, w);
  fft1_init (&f->cols, h);
  f->line = g_new (cpx, h);
  return f;
}

static void
fft2_free (Fft2 *f)
{
  g_free (f->rows.tw); g_free (f->rows.rev);
  g_free (f->cols.tw); g_free (f->cols.rev);
  g_free (f->line);
  g_free (f);
}

/* In place 2-D transform. Only the first rows_used rows can be non-zero
 * before a forward transform, so the row pass skips the rest. */
static void
fft2_run (Fft2 *f, cpx *d, gboolean inverse, gint rows_used)
{
  for (gint y = 0; y < MIN (rows_used, f->h); y++)
    fft1_run (&f->rows, d + y * f->w, inverse);
  for (gint x = 0; x < f->w; x++)
    {
      for (gint y = 0; y < f->h; y++)
        f->line[y] = d[y * f->w + x];
      fft1_run (&f->cols, f->line, inverse);
      for (gint y = 0; y < f->h; y++)
        d[y * f->w + x] = f->line[y];
    }
}

/* Spectra of two real h x w images (b may be NULL = zero), zero padded to
 * the plan size: packed as a + ib, transformed once, split by symmetry:
 * A[k] = (Z[k] + conj Z[-k]) / 2, B[k] = (Z[k] - conj Z[-k]) / 2i. */
static void
fft_real_pair (Fft2 *f, const gfloat *a, const gfloat *b, gint h, gint w,
               cpx *fa, cpx *fb)
{
  gint FW = f->w, FH = f->h;
  g_autofree cpx *z = g_new0 (cpx, FH * FW);

  for (gint y = 0; y < h; y++)
    for (gint x = 0; x < w; x++)
      {
        z[y * FW + x].re = a[y * w + x];
        z[y * FW + x].im = b ? b[y * w + x] : 0;
      }
  fft2_run (f, z, FALSE, h);
  for (gint y = 0; y < FH; y++)
    for (gint x = 0; x < FW; x++)
      {
        cpx p = z[y * FW + x];
        cpx q = z[((FH - y) % FH) * FW + (FW - x) % FW];
        fa[y * FW + x] = (cpx) { (p.re + q.re) / 2, (p.im - q.im) / 2 };
        if (fb)
          fb[y * FW + x] = (cpx) { (p.im + q.im) / 2, (q.re - p.re) / 2 };
      }
}

/* Spectra of an image taking part in a correlation: z, mask, z^2. */
typedef struct
{
  gint h, w;
  cpx *fz, *fm, *fz2;
} Spec;

static void
spec_init (Spec *s, Fft2 *f, const gfloat *z, const gfloat *m, gint h, gint w)
{
  g_autofree gfloat *z2 = g_new (gfloat, h * w);

  for (gint p = 0; p < h * w; p++)
    z2[p] = z[p] * z[p];
  s->h = h; s->w = w;
  s->fz = g_new (cpx, f->h * f->w);
  s->fm = g_new (cpx, f->h * f->w);
  s->fz2 = g_new (cpx, f->h * f->w);
  fft_real_pair (f, z, m, h, w, s->fz, s->fm);
  fft_real_pair (f, z2, NULL, h, w, s->fz2, NULL);
}

static void
spec_clear (Spec *s)
{
  g_clear_pointer (&s->fz, g_free);
  g_clear_pointer (&s->fm, g_free);
  g_clear_pointer (&s->fz2, g_free);
}

typedef struct
{
  gdouble score;
  gint    rot, dy, dx;   /* B rotated by rot, top-left at (dy, dx) in A */
} Hit;

/* Best correlation of B (spectra of an already rotated image) against A
 * over all translations; updates *best. x1, x2: scratch of plan size. */
static void
correlate (Fft2 *f, const Spec *A, const Spec *B, gfloat minov, gint rot,
           cpx *x1, cpx *x2, Hit *best)
{
  gint FW = f->w, FH = f->h, FN = FW * FH;

  for (gint k = 0; k < FN; k++)
    {
      cpx a, b;
#define MULC(u, v) ((cpx) { u.re * v.re + u.im * v.im, u.im * v.re - u.re * v.im })
      a = MULC (A->fz[k], B->fz[k]);
      b = MULC (A->fm[k], B->fm[k]);
      x1[k] = (cpx) { a.re - b.im, a.im + b.re };    /* num + i overlap */
      a = MULC (A->fz2[k], B->fm[k]);
      b = MULC (A->fm[k], B->fz2[k]);
      x2[k] = (cpx) { a.re - b.im, a.im + b.re };    /* ea + i eb */
#undef MULC
    }
  fft2_run (f, x1, TRUE, FH);
  fft2_run (f, x2, TRUE, FH);
  for (gint y = 0; y < FH; y++)
    for (gint x = 0; x < FW; x++)
      {
        gint k = y * FW + x;
        gfloat num = x1[k].re / FN, ov = x1[k].im / FN;
        gfloat den = (x2[k].re / FN) * (x2[k].im / FN);
        gdouble c;

        if (ov < minov || den <= 1e-9f)
          continue;
        c = num / sqrt (den);
        if (c > best->score)
          {
            best->score = c;
            best->rot = rot;
            /* valid shifts are -(B->h - 1)..A->h - 1, one period */
            best->dy = y < A->h ? y : y - FH;
            best->dx = x < A->w ? x : x - FW;
          }
      }
}

/* ---- templates, rotation --------------------------------------------- */

static void
tpl_to_float (const gint8 *t, gfloat *z, gfloat *m)
{
  for (gint p = 0; p < N; p++)
    {
      gboolean in = t[p] != -128;
      z[p] = in ? t[p] / Z_SCALE : 0;
      m[p] = in;
    }
}

/* Forward map of a rotation by deg about the image centre (the
 * scipy.ndimage.rotate convention): p -> R (p - c) + c on (y, x),
 * R = [[cos, -sin], [sin, cos]]. */
static void
rot_matrix (gdouble deg, gdouble R[4])
{
  gdouble a = deg * G_PI / 180;

  R[0] = cos (a); R[1] = -sin (a);
  R[2] = sin (a); R[3] = cos (a);
}

/* Sample a template at (qy, qx): bilinear z, nearest-neighbour mask. */
static gboolean
sample (const gfloat *fz, const gfloat *fm, gdouble qy, gdouble qx, gfloat *out)
{
  gint ny, nx, y0, x0;
  gdouble fy, fx, v = 0;

  /* Stored pose data is untrusted.  Check bounds before converting a
   * floating-point coordinate to gint, where an extreme finite value would
   * otherwise be undefined or implementation-defined.  The wider interval
   * keeps valid bilinear edge samples. */
  if (!isfinite (qy) || !isfinite (qx) ||
      qy < -1.0 || qy > H || qx < -1.0 || qx > W)
    return FALSE;
  ny = (gint) lrint (qy);
  nx = (gint) lrint (qx);
  y0 = (gint) floor (qy);
  x0 = (gint) floor (qx);
  fy = qy - y0;
  fx = qx - x0;

  if (ny < 0 || ny >= H || nx < 0 || nx >= W || !fm[ny * W + nx])
    return FALSE;
  for (gint dy = 0; dy <= 1; dy++)
    for (gint dx = 0; dx <= 1; dx++)
      {
        gint yy = y0 + dy, xx = x0 + dx;
        if (yy >= 0 && yy < H && xx >= 0 && xx < W)
          v += (dy ? fy : 1 - fy) * (dx ? fx : 1 - fx) * fz[yy * W + xx];
      }
  *out = v;
  return TRUE;
}

static void
rotate_tpl (const gfloat *fz, const gfloat *fm, gdouble deg, gfloat *z, gfloat *m)
{
  gdouble R[4], cy = (H - 1) / 2.0, cx = (W - 1) / 2.0;

  rot_matrix (deg, R);
  for (gint y = 0; y < H; y++)
    for (gint x = 0; x < W; x++)
      {
        /* inverse map: source = R^T (p - c) + c */
        gdouble sy = R[0] * (y - cy) + R[2] * (x - cx) + cy;
        gdouble sx = R[1] * (y - cy) + R[3] * (x - cx) + cx;
        gint p = y * W + x;

        m[p] = sample (fz, fm, sy, sx, &z[p]);
        if (!m[p])
          z[p] = 0;
      }
}

/* Spectra of a template for every rotation of the search. */
static Spec *
rotated_specs (Fft2 *f, const gint8 *tpl)
{
  Spec *s = g_new0 (Spec, N_ROTS);
  g_autofree gfloat *fz = g_new (gfloat, N), *fm = g_new (gfloat, N);
  g_autofree gfloat *z = g_new (gfloat, N), *m = g_new (gfloat, N);

  tpl_to_float (tpl, fz, fm);
  for (gint r = 0; r < N_ROTS; r++)
    {
      rotate_tpl (fz, fm, -ROT_MAX + r * ROT_STEP, z, m);
      spec_init (&s[r], f, z, m, H, W);
    }
  return s;
}

static void
specs_free (Spec *s, gint n)
{
  for (gint i = 0; i < n; i++)
    spec_clear (&s[i]);
  g_free (s);
}

/* ---- model: spanning forest of template poses ------------------------ */

/* Pose: template point q -> island canvas a q + b, a a rotation. */
typedef struct
{
  gdouble a[4], b[2];
} Pose;

static Pose
pose_compose (const Pose *p, const Pose *q)    /* p after q */
{
  Pose r;

  r.a[0] = p->a[0] * q->a[0] + p->a[1] * q->a[2];
  r.a[1] = p->a[0] * q->a[1] + p->a[1] * q->a[3];
  r.a[2] = p->a[2] * q->a[0] + p->a[3] * q->a[2];
  r.a[3] = p->a[2] * q->a[1] + p->a[3] * q->a[3];
  r.b[0] = p->a[0] * q->b[0] + p->a[1] * q->b[1] + p->b[0];
  r.b[1] = p->a[2] * q->b[0] + p->a[3] * q->b[1] + p->b[1];
  return r;
}

static Pose
pose_invert (const Pose *p)                    /* rotation: inverse = transpose */
{
  Pose r = { { p->a[0], p->a[2], p->a[1], p->a[3] }, { 0, 0 } };

  r.b[0] = -(r.a[0] * p->b[0] + r.a[1] * p->b[1]);
  r.b[1] = -(r.a[2] * p->b[0] + r.a[3] * p->b[1]);
  return r;
}

/* Pose of B in A's frame from a hit (B rotated about its centre, then its
 * top-left placed at (dy, dx) in A). */
static Pose
pose_from_hit (const Hit *h)
{
  Pose p;
  gdouble cy = (H - 1) / 2.0, cx = (W - 1) / 2.0;

  rot_matrix (h->rot, p.a);
  p.b[0] = cy - (p.a[0] * cy + p.a[1] * cx) + h->dy;
  p.b[1] = cx - (p.a[2] * cy + p.a[3] * cx) + h->dx;
  return p;
}

typedef struct
{
  Spec  spec;
  gint  plan;          /* index into the model's plans */
} Island;

struct _S00a8Model
{
  guint   n_islands;
  Island *isl;
  guint   n_plans;
  Fft2   *plans[MAX_PLANS];
};

static gint
pow2_at_least (gint v)
{
  gint p = 1;

  while (p < v)
    p <<= 1;
  return p;
}

static gint
model_plan (S00a8Model *md, gint fh, gint fw)
{
  for (guint i = 0; i < md->n_plans; i++)
    if (md->plans[i]->h == fh && md->plans[i]->w == fw)
      return i;
  g_assert (md->n_plans < MAX_PLANS);
  md->plans[md->n_plans] = fft2_new (fh, fw);
  return md->n_plans++;
}

/* Render the islands (average of the warped templates), crop them to
 * their bounding boxes and compute their spectra. */
static S00a8Model *
model_render (const gint8 *tpls, guint n, const gint *island, const Pose *pose)
{
  S00a8Model *md = g_new0 (S00a8Model, 1);
  g_autofree gfloat *fz = g_new (gfloat, N), *fm = g_new (gfloat, N);
  g_autofree gfloat *Z = g_new (gfloat, CH * CW), *C = g_new (gfloat, CH * CW);
  g_autofree gfloat *cz = g_new (gfloat, CH * CW), *cm = g_new (gfloat, CH * CW);

  for (guint i = 0; i < n; i++)
    md->n_islands = MAX (md->n_islands, (guint) (island[i] + 1));
  md->isl = g_new0 (Island, md->n_islands);

  for (guint k = 0; k < md->n_islands; k++)
    {
      gint y0 = CH, y1 = -1, x0 = CW, x1 = -1, bh, bw;

      memset (Z, 0, CH * CW * sizeof (gfloat));
      memset (C, 0, CH * CW * sizeof (gfloat));
      for (guint i = 0; i < n; i++)
        {
          Pose inv;

          if (island[i] != (gint) k)
            continue;
          tpl_to_float (tpls + (gsize) i * N, fz, fm);
          inv = pose_invert (&pose[i]);
          for (gint y = 0; y < CH; y++)
            for (gint x = 0; x < CW; x++)
              {
                gfloat v;
                if (sample (fz, fm, inv.a[0] * y + inv.a[1] * x + inv.b[0],
                            inv.a[2] * y + inv.a[3] * x + inv.b[1], &v))
                  {
                    Z[y * CW + x] += v;
                    C[y * CW + x] += 1;
                  }
              }
        }
      for (gint y = 0; y < CH; y++)
        for (gint x = 0; x < CW; x++)
          if (C[y * CW + x] > 0)
            {
              y0 = MIN (y0, y); y1 = MAX (y1, y);
              x0 = MIN (x0, x); x1 = MAX (x1, x);
            }
      if (y1 < 0)
        {
          s00a8_model_free (md);
          return NULL;
        }
      bh = y1 - y0 + 1;
      bw = x1 - x0 + 1;
      for (gint y = 0; y < bh; y++)
        for (gint x = 0; x < bw; x++)
          {
            gfloat c = C[(y + y0) * CW + x + x0];
            cz[y * bw + x] = c > 0 ? Z[(y + y0) * CW + x + x0] / c : 0;
            cm[y * bw + x] = c > 0;
          }
      md->isl[k].plan = model_plan (md, pow2_at_least (bh + H - 1),
                                    pow2_at_least (bw + W - 1));
      spec_init (&md->isl[k].spec, md->plans[md->isl[k].plan], cz, cm, bh, bw);
    }
  return md;
}

void
s00a8_model_free (S00a8Model *md)
{
  if (!md)
    return;
  for (guint k = 0; k < md->n_islands; k++)
    spec_clear (&md->isl[k].spec);
  g_free (md->isl);
  for (guint i = 0; i < md->n_plans; i++)
    fft2_free (md->plans[i]);
  g_free (md);
}

guint
s00a8_model_islands (S00a8Model *md)
{
  return md->n_islands;
}

/* Incremental enrollment: every added template is aligned against the
 * earlier ones right away (while the user lifts the finger), so finishing
 * the model only has to lay out the forest and render the islands. */
struct _S00a8Aligner
{
  Fft2      *plan;
  GArray    *base;      /* Spec per template, unrotated */
  GArray    *hits;      /* Hit rows: hit (i, j), i < j, at j * (j - 1) / 2 + i */
  GByteArray *tpls;
  cpx       *x1, *x2;
};

S00a8Aligner *
s00a8_aligner_new (void)
{
  S00a8Aligner *al = g_new0 (S00a8Aligner, 1);

  al->plan = fft2_new (PAIR_FH, PAIR_FW);
  al->base = g_array_new (FALSE, TRUE, sizeof (Spec));
  al->hits = g_array_new (FALSE, TRUE, sizeof (Hit));
  al->tpls = g_byte_array_new ();
  al->x1 = g_new (cpx, PAIR_FH * PAIR_FW);
  al->x2 = g_new (cpx, PAIR_FH * PAIR_FW);
  return al;
}

void
s00a8_aligner_free (S00a8Aligner *al)
{
  if (!al)
    return;
  for (guint i = 0; i < al->base->len; i++)
    spec_clear (&g_array_index (al->base, Spec, i));
  g_array_unref (al->base);
  g_array_unref (al->hits);
  g_byte_array_unref (al->tpls);
  fft2_free (al->plan);
  g_free (al->x1);
  g_free (al->x2);
  g_free (al);
}

void
s00a8_aligner_add (S00a8Aligner *al, const gint8 *tpl)
{
  g_autofree gfloat *z = g_new (gfloat, N), *m = g_new (gfloat, N);
  guint j = al->base->len;
  Spec sp = { 0 };

  if (j > 0)
    {
      Spec *rs = rotated_specs (al->plan, tpl);

      for (guint i = 0; i < j; i++)
        {
          Hit h = { -1, 0, 0, 0 };
          for (gint r = 0; r < N_ROTS; r++)
            correlate (al->plan, &g_array_index (al->base, Spec, i), &rs[r],
                       PAIR_OVERLAP, -ROT_MAX + r * ROT_STEP, al->x1, al->x2, &h);
          g_array_append_val (al->hits, h);
        }
      specs_free (rs, N_ROTS);
    }
  tpl_to_float (tpl, z, m);
  spec_init (&sp, al->plan, z, m, H, W);
  g_array_append_val (al->base, sp);
  g_byte_array_append (al->tpls, (const guint8 *) tpl, N);
}

/* Lay the templates out in islands (maximum spanning forest over links
 * with score >= LINK_SCORE) and render the model. Writes
 * S00A8_POSE_LEN doubles per template to poses_out: island,
 * a00, a01, a10, a11, b0, b1. */
S00a8Model *
s00a8_aligner_finish (S00a8Aligner *al, gdouble *poses_out)
{
  guint n = al->base->len;
  const gint8 *tpls = (const gint8 *) al->tpls->data;
  const Hit *hit = (const Hit *) al->hits->data;
  g_autofree gint *island = g_new (gint, n);
  g_autofree Pose *pose = g_new0 (Pose, n);
  gint n_islands = 0;
  S00a8Model *md;

#define HIT(i, j) (&hit[(j) * ((j) - 1) / 2 + (i)])   /* i < j: j in i */
  for (guint i = 0; i < n; i++)
    island[i] = -1;
  for (;;)
    {
      /* a new island, rooted at the unplaced template with most coverage */
      gint root = -1;
      guint best_cov = 0;

      for (guint i = 0; i < n; i++)
        {
          guint cov = 0;
          if (island[i] >= 0)
            continue;
          for (gint p = 0; p < N; p++)
            cov += tpls[(gsize) i * N + p] != -128;
          if (root < 0 || cov > best_cov)
            root = i, best_cov = cov;
        }
      if (root < 0)
        break;
      island[root] = n_islands;
      pose[root] = (Pose) { { 1, 0, 0, 1 }, { (CH - H) / 2, (CW - W) / 2 } };

      for (;;)   /* Prim: strongest link between this island and unplaced */
        {
          gdouble bs = LINK_SCORE;
          gint bi = -1, bj = -1;

          for (guint j = 1; j < n; j++)
            for (guint i = 0; i < j; i++)
              {
                gboolean ii = island[i] == n_islands, jj = island[j] == n_islands;
                gboolean ifree = island[i] < 0, jfree = island[j] < 0;
                if (!((ii && jfree) || (jj && ifree)))
                  continue;
                if (HIT (i, j)->score >= bs)
                  bs = HIT (i, j)->score, bi = i, bj = j;
              }
          if (bi < 0)
            break;
          {
            Pose p = pose_from_hit (HIT (bi, bj));          /* bj -> bi */
            if (island[bi] == n_islands)
              {
                pose[bj] = pose_compose (&pose[bi], &p);
                island[bj] = n_islands;
              }
            else
              {
                Pose q = pose_invert (&p);                  /* bi -> bj */
                pose[bi] = pose_compose (&pose[bj], &q);
                island[bi] = n_islands;
              }
          }
        }
      n_islands++;
    }
#undef HIT

  if (poses_out)
    for (guint i = 0; i < n; i++)
      {
        gdouble *o = poses_out + S00A8_POSE_LEN * i;
        o[0] = island[i];
        memcpy (o + 1, pose[i].a, 4 * sizeof (gdouble));
        memcpy (o + 5, pose[i].b, 2 * sizeof (gdouble));
      }
  md = model_render (tpls, n, island, pose);
  if (md != NULL)
    fp_dbg ("match33: model of %u templates in %u islands", n, md->n_islands);
  return md;
}


/* Rebuild a model from stored templates and poses (no alignment). The
 * poses come from a stored print, so every value is validated before use:
 * island ids must be compact indices in [0, n) and all pose numbers
 * finite. Returns NULL on malformed data instead of trusting it. */
S00a8Model *
s00a8_model_new (const gint8 *tpls, guint n, const gdouble *poses)
{
  g_autofree gint *island = g_new (gint, n);
  g_autofree Pose *pose = g_new (Pose, n);
  g_autofree gboolean *seen_island = g_new0 (gboolean, n);
  guint max_island = 0, n_islands = 0;

  if (n == 0)
    return NULL;
  for (guint i = 0; i < n; i++)
    {
      const gdouble *o = poses + S00A8_POSE_LEN * i;

      if (!isfinite (o[0]) || o[0] < 0 || o[0] >= n ||
          o[0] != (gdouble) (gint) o[0])
        return NULL;
      island[i] = (gint) o[0];
      if (!seen_island[island[i]])
        {
          seen_island[island[i]] = TRUE;
          n_islands++;
          max_island = MAX (max_island, (guint) island[i]);
        }
      for (guint k = 1; k < 5; k++)
        if (!isfinite (o[k]) || fabs (o[k]) > MAX_POSE_MATRIX)
          return NULL;
      for (guint k = 5; k < S00A8_POSE_LEN; k++)
        if (!isfinite (o[k]) || fabs (o[k]) > MAX_POSE_OFFSET)
          return NULL;
      if (fabs (o[1] * o[1] + o[3] * o[3] - 1) > 1e-3 ||
          fabs (o[2] * o[2] + o[4] * o[4] - 1) > 1e-3 ||
          fabs (o[1] * o[2] + o[3] * o[4]) > 1e-3 ||
          fabs (o[1] * o[4] - o[2] * o[3] - 1) > 1e-3)
        return NULL;
      memcpy (pose[i].a, o + 1, 4 * sizeof (gdouble));
      memcpy (pose[i].b, o + 5, 2 * sizeof (gdouble));
    }
  if (n_islands != max_island + 1)
    return NULL;
  return model_render (tpls, n, island, pose);
}

/* Best correlation of a probe template against any island. Coarse to
 * fine: every island at every second rotation (4 degree steps), then the
 * neighbouring 2 degree rotations of the REFINE_TOP best (island,
 * rotation) pairs. Probe spectra are computed per FFT size on demand. */
gdouble
s00a8_model_score (S00a8Model *md, const gint8 *probe)
{
  g_autofree gfloat *fz = g_new (gfloat, N), *fm = g_new (gfloat, N);
  g_autofree gfloat *z = g_new (gfloat, N), *m = g_new (gfloat, N);
  g_autofree gdouble *score = g_new (gdouble, (gsize) md->n_islands * N_ROTS);
  Spec rs[MAX_PLANS][N_ROTS];
  cpx *x1[MAX_PLANS] = { 0 }, *x2[MAX_PLANS] = { 0 };
  gboolean have[N_ROTS] = { 0 };
  Hit best = { -1, 0, 0, 0 };
  gint top[REFINE_TOP];

  memset (rs, 0, sizeof (rs));
  tpl_to_float (probe, fz, fm);
  for (gsize i = 0; i < (gsize) md->n_islands * N_ROTS; i++)
    score[i] = G_MAXDOUBLE;              /* not evaluated */
  for (guint p = 0; p < md->n_plans; p++)
    {
      x1[p] = g_new (cpx, md->plans[p]->h * md->plans[p]->w);
      x2[p] = g_new (cpx, md->plans[p]->h * md->plans[p]->w);
    }

#define EVAL(k, r) G_STMT_START {                                           \
    if (score[(k) * N_ROTS + (r)] == G_MAXDOUBLE)                           \
      {                                                                     \
        gint pl = md->isl[k].plan;                                          \
        Hit h = { -1, 0, 0, 0 };                                            \
        if (!have[r])                                                       \
          {                                                                 \
            rotate_tpl (fz, fm, -ROT_MAX + (r) * ROT_STEP, z, m);           \
            for (guint q = 0; q < md->n_plans; q++)                         \
              spec_init (&rs[q][r], md->plans[q], z, m, H, W);              \
            have[r] = TRUE;                                                 \
          }                                                                 \
        correlate (md->plans[pl], &md->isl[k].spec, &rs[pl][r], MIN_OVERLAP,\
                   -ROT_MAX + (r) * ROT_STEP, x1[pl], x2[pl], &h);          \
        score[(k) * N_ROTS + (r)] = h.score;                                \
        if (h.score > best.score)                                           \
          best = h;                                                         \
      }                                                                     \
  } G_STMT_END

  for (guint k = 0; k < md->n_islands; k++)
    for (gint r = 0; r < N_ROTS; r += 2)
      EVAL (k, r);

  for (gint t = 0; t < REFINE_TOP; t++)
    {
      gint bi = -1;
      top[t] = -1;
      for (gint i = 0; i < (gint) md->n_islands * N_ROTS; i++)
        {
          gboolean taken = FALSE;
          if (score[i] == G_MAXDOUBLE || score[i] < 0)
            continue;
          for (gint u = 0; u < t; u++)
            taken |= top[u] == i;
          if (!taken && (bi < 0 || score[i] > score[bi]))
            bi = i;
        }
      top[t] = bi;
    }
  for (gint t = 0; t < REFINE_TOP; t++)
    if (top[t] >= 0)
      {
        gint k = top[t] / N_ROTS, r = top[t] % N_ROTS;
        if (r > 0)
          EVAL (k, r - 1);
        if (r < N_ROTS - 1)
          EVAL (k, r + 1);
      }
#undef EVAL

  for (guint q = 0; q < md->n_plans; q++)
    {
      for (gint r = 0; r < N_ROTS; r++)
        spec_clear (&rs[q][r]);
      g_free (x1[q]);
      g_free (x2[q]);
    }
  fp_dbg ("match33: best %.3f at rotation %d, offset (%d, %d)",
          best.score, best.rot, best.dy, best.dx);
  return best.score;
}

/* Best correlation of the probe with rotated/shifted copies of itself,
 * excluding translations within +-SELF_EXCLUDE pixels of the identity. */
gdouble
s00a8_match_self_score (const gint8 *probe)
{
  Fft2 *f = fft2_new (PAIR_FH, PAIR_FW);
  gint FW = f->w, FH = f->h, FN = FW * FH;
  g_autofree gfloat *fz = g_new (gfloat, N), *fm = g_new (gfloat, N);
  g_autofree gfloat *z = g_new (gfloat, N), *m = g_new (gfloat, N);
  g_autofree cpx *x1 = g_new (cpx, FN), *x2 = g_new (cpx, FN);
  Spec base = { 0 };
  gdouble best = -1;

  tpl_to_float (probe, fz, fm);
  spec_init (&base, f, fz, fm, H, W);
  for (gint deg = -ROT_MAX; deg <= ROT_MAX; deg += SELF_ROT_STEP)
    {
      Spec rs = { 0 };

      rotate_tpl (fz, fm, deg, z, m);
      spec_init (&rs, f, z, m, H, W);
      for (gint k = 0; k < FN; k++)
        {
          cpx a, b;
#define MULC(u, v) ((cpx) { u.re * v.re + u.im * v.im, u.im * v.re - u.re * v.im })
          a = MULC (base.fz[k], rs.fz[k]);
          b = MULC (base.fm[k], rs.fm[k]);
          x1[k] = (cpx) { a.re - b.im, a.im + b.re };
          a = MULC (base.fz2[k], rs.fm[k]);
          b = MULC (base.fm[k], rs.fz2[k]);
          x2[k] = (cpx) { a.re - b.im, a.im + b.re };
#undef MULC
        }
      spec_clear (&rs);
      fft2_run (f, x1, TRUE, FH);
      fft2_run (f, x2, TRUE, FH);
      for (gint y = 0; y < FH; y++)
        for (gint x = 0; x < FW; x++)
          {
            gint k = y * FW + x, dy = y < FH / 2 ? y : y - FH, dx = x < FW / 2 ? x : x - FW;
            gfloat ov = x1[k].im / FN, den = (x2[k].re / FN) * (x2[k].im / FN);

            if (ABS (dy) <= SELF_EXCLUDE && ABS (dx) <= SELF_EXCLUDE)
              continue;
            if (ov < MIN_OVERLAP || den <= 1e-9f)
              continue;
            best = MAX (best, (x1[k].re / FN) / sqrt (den));
          }
    }
  spec_clear (&base);
  fft2_free (f);
  return best;
}

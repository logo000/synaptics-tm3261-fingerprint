# Synaptics TM3261 fingerprint driver for Linux

A native [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)
driver for the Synaptics TM3261 USB fingerprint reader (sensor type
0x2449, USB id `06cb:00a8`), found in several SCHENKER / Clevo laptops. It makes the reader work with the normal
Linux fingerprint stack: fprintd, and the fingerprint settings in GNOME and
KDE.

The reader has no on-chip matcher, so the matching runs on the host: enrol
stitches several presses into a mosaic of the finger and verify correlates
against it.

## Contents

```
src/                the driver
  s00a8.c           device lifecycle, capture loop, enrol/verify
  s00a8-tls.c       the reader's TLS 1.2 secure channel
  s00a8-pair.c      one-time pairing and key storage
  s00a8-program.c   capture program assembly
  s00a8-image.c     raw frame decoding (144 x 56)
  s00a8-match.c     host-side mosaic matcher
  s00a8-*-data.c    constant tables the reader needs (see below)
meson-snippet.txt   how to register the driver in libfprint's build
```

## Building

The driver builds as part of libfprint:

```bash
git clone https://gitlab.freedesktop.org/libfprint/libfprint
cp -r src libfprint/libfprint/drivers/synaptics00a8
# apply the two edits from meson-snippet.txt to libfprint's meson files
cd libfprint
meson setup build -Ddrivers=default
ninja -C build
```

Install it over your distribution's libfprint, or package it. Then enrol a
finger in your desktop's fingerprint settings and use it for login and
`sudo`.

## The `s00a8-*-data.c` tables

These hold constant values the reader needs to run — its capture program,
register setup and scan configuration. They were recovered by reverse
engineering the vendor driver for interoperability, the way other libfprint
drivers carry vendor register tables. They are plain data, never executed.

## Security notes

- Pairing is trust-on-first-use: the family-wide pairing secret is public,
  so first pairing sets up the channel but does not prove the reader's
  identity.
- Captured frames are not authenticated end to end; the reader offers no
  way to bind them to the secure channel. Both are properties of the
  hardware, not of this driver.

## Status

Pairing, the secure channel, capture, enrol and verify run on real
hardware. The matching thresholds were tuned on a small sample; the
false-accept rate is not yet measured widely.

## License

LGPL-2.1-or-later, matching libfprint.

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
drivers carry vendor register tables. They are data in the host library; some encode instructions interpreted by
the sensor. No vendor DLL is loaded or executed on the host.

## Calibration and upgrades

The driver stores the raw calibration frame and its corrected empty-sensor
baseline together in `capture-reference-v1.bin`, next to the device pairing.
Inside fprintd this is under `/var/lib/fprint/synaptics-06cb-00a8/devices/`;
outside fprintd it uses the user's libfprint data directory. Keep these
private state directories owned by the account running the driver.

Legacy `baseline.bin` files are ignored: they do not contain the raw
calibration needed to reproduce the original image. On the first use after
upgrading, leave the sensor empty for initial calibration before placing a
finger. Existing enrolled fingerprints and pairing keys are preserved.

## Security notes

This is an experimental driver and custom biometric matcher, not a certified
authentication system. See [SECURITY.md](SECURITY.md) for the threat model,
review results and remaining limitations.

- Pairing uses a sensor-family signing constant and trusts the sensor key
  obtained during first pairing. Subsequent handshakes check possession of
  the saved sensor key. This does not establish manufacturer authenticity
  on first use. Do not delete pairing state automatically on handshake failure.
- Image frames arrive on a separate USB endpoint without cryptographic
  authentication or a binding to the command channel. Physical USB access
  can permit image injection or replay. No liveness detection is implemented.
- The sensor's TLS-like protocol omits record sequence numbers from its
  MAC, so authenticated records have no per-record replay protection within
  a session. It is not interchangeable with a standard TLS implementation.
- Matching thresholds were tuned on a small sample. A population-level
  false-accept rate has not been established. Keep password fallback available
  and do not rely on this driver for high-assurance biometric authentication.

## Tests

The hardware-independent regression suite compiles the production helpers
with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
# Debian build dependencies for the standalone tests
sudo apt install clang pkg-config libglib2.0-dev libgusb-dev libssl-dev python3
./tests/run.sh
```

Use `SANITIZE=0 CC=gcc ./tests/run.sh` for an ordinary GCC build. Tests use
synthetic data and temporary files; they do not access the scanner or stored
fingerprints. The cache test extracts the actual helper functions from the
driver because the rest of that file requires libfprint's device lifecycle.

## Status

Pairing, capture, enrolment and fingerprint verification have been exercised
on one real 06cb:00a8 device. The calibration fix passed two empty-sensor tests,
a subsequent successful fingerprint verification and user confirmation of
working authentication. The additional parser hardening and cleanup pass
standalone regression tests and a full libfprint build; they have not received
a separate hardware run. See the review record in [SECURITY.md](SECURITY.md).

## License

LGPL-2.1-or-later, matching libfprint.

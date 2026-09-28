# Security review — 2026-09-27

## Scope and method

Reviewed all driver translation units, the shared header, build integration
and documentation. Areas checked include USB response lengths, command
assembly, TLS record/handshake parsing, pairing persistence, calibration
storage, image decoding, stored template validation, matcher bounds and
asynchronous ownership/cancellation. The opaque sensor tables were checked
for references and their retained bytes compared with the existing repository;
the sensor-side meaning of every byte was not independently verified.

Validation uses a full libfprint 1.94.9 build, Clang static analysis of all ten
translation units, and hardware-independent regression tests with ASan/UBSan.
No real fingerprint images, private pairing keys, logs or local binaries are
part of this repository. This review is not a proof of absence of vulnerabilities
or a biometric certification.

## Changes from the review

- Corrected calibration reuse across device opens. Previously the corrected
  baseline was reused as the raw offset calibration, causing a blank sensor
  to be treated as a finger. Persist both arrays together, reject legacy or
  malformed references and create the cache with mode 0600.
- Guarded the failed model-render path before accessing the model in logging.
  A completely masked enrollment template reproduces that failure.
- Rejected oversized TLS plaintext before length arithmetic, including
  SIZE_MAX. Current command callers use bounded sizes; this is defensive
  hardening of the helper rather than a demonstrated USB-triggered overflow.
- Checked handshake digest-update failures and enforced the expected order
  and uniqueness of ServerHello, CertificateRequest and ServerHelloDone.
  Reject nonempty ServerHelloDone and unsupported compression.
- Moved the timeslot instruction's first byte read after its length check.
  Existing callers pass positive lengths; the empty-input regression covers
  the helper boundary.
- Removed unused device fields, an unused 10,500-byte alternative configuration
  and its declaration. Retained an initialization probe because its hardware
  sequencing effects have not been disproved. Fixed the fallback probe-ID
  allocation leak and replaced unused exchange-label storage with debug logging.
- Corrected stale hardware comments and security claims in the documentation.
  Matching thresholds and the on-disk fingerprint template format are unchanged.

## Validation results

The local regression suite (not included in this repository) checks:

- TLS record round trips over all plaintext sizes 0–255, ciphertext tampering,
  short records, extreme lengths, duplicate/out-of-order handshake messages,
  unsupported compression and 2,000 deterministic random parser inputs.
- Image truncation and decoding, capture-command chunk boundaries and extreme
  factory-calibration bit packing, including a constant stream.
- Empty enrollment, invalid/nonfinite stored poses, a synthetic self-match and
  rejection of a fully masked probe.
- Bounded pairing-file reads, invalid P-256 points and certificate/key mismatch.
- Distinct raw/corrected calibration round trips and invalid cache rejection.

The static analyzer's remaining reports were inspected rather than suppressed:
its leak reports concern GLib automatic cleanup variables; its matcher reports
assume skipped initialization loops or inconsistent private FFT/model dimensions.
Production FFT sizes are positive powers of two, stored template counts are
bounded to 15, and each rendered island owns a valid plan. The regression suite
exercises the relevant helper paths with sanitizers. Static-analysis success
alone is not treated as a clean bill of health.

Hardware evidence applies to the calibration repair: two empty-sensor checks
waited without matching, including after reopening, then the enrolled finger
matched successfully. Authentication was subsequently confirmed by the user.
The additional review changes have not been separately tested on hardware.

## Remaining limitations and assumptions

- First pairing is trust-on-first-use using a public sensor-family signing
  constant. A malicious device present during initial pairing can supply its
  own key. A saved key pins subsequent sessions; it is not a manufacturer trust
  chain. Interrupted first pairing still requires a trusted physical device.
- Raw USB images are unauthenticated. The sensor protocol does not bind them
  to a TLS session, and this driver provides no liveness detection.
- The command protocol omits sequence numbers from its MAC. Replays within
  a session are not prevented. This implementation follows sensor behavior;
  do not describe it as standards-compliant TLS.
- The custom image-correlation matcher has no representative measured
  false-accept rate. Synthetic tests verify code behavior, not biometric
  security. Larger independent genuine/impostor and presentation-attack
  evaluations remain necessary.
- Calibration starts with an empty sensor when no valid cache exists. A finger
  present during this first calibration can contaminate the reference and
  cause recognition failures. Leave the sensor empty during first setup.
- State storage assumes trusted, private directories owned by the service
  account (fprintd's root-owned StateDirectory, or the direct caller's data
  directory). This is not a sandbox against an attacker who can rewrite those
  directories or run arbitrary code as that account. Do not run the driver as
  root with a user-controlled STATE_DIRECTORY or XDG data directory.
- USB operations have timeouts and recovery drains are bounded. Matching runs
  in the main loop and can delay cancellation while computing a score or
  enrollment alignment; it is bounded by image dimensions and template count.

To report a problem, include the affected commit, sensor model and a minimal
reproducer. Do not attach fingerprint templates, raw captures or private keys
to public issues.

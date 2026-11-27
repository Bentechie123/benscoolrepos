#!/usr/bin/env python3
"""Build the root certificate data for Ben's Cert Fix.

Reads Mozilla's CA bundle (cacert.pem from https://curl.se/ca/), picks the
roots listed in ROOTS, and writes:

  layout/Library/BensCertFix/roots.plist   - what the device tool installs
  certs/<name>.cer                          - each root as DER (for the profile)
  ROOTS.md                                  - human-readable list with fingerprints

Each plist entry holds the values iOS keeps in the tsettings table of
/private/var/Keychains/TrustStore.sqlite3 for a user-trusted root:
  sha1  - SHA-1 of the whole DER certificate (the key iOS looks up)
  subj  - the certificate subject, re-encoded the way iOS stores it
          (PrintableString values upper-cased; same rule as ADVTrustStore)
  data  - the DER certificate
The trust settings (tset) value is the same empty-array plist for every row
and is written by the device tool.

With a third argument (the repo root) it also writes the site files: a
configuration profile (assets/BensCertFix.mobileconfig), each root as a .crt
(assets/certs/), and certfix.html, which installs them on devices that
aren't jailbroken.

Usage: make_roots.py <cacert.pem> <output project dir> [site dir]
"""
import base64
import datetime
import hashlib
import plistlib
import re
import sys
import uuid
from pathlib import Path

# Fixed namespace so the profile's UUIDs stay the same between builds.
PROFILE_NS = uuid.UUID("6f1c2b1e-6a52-4c11-9d1e-2b7f6c3a9e10")

ROOTS = [
    # Let's Encrypt
    "ISRG Root X1", "ISRG Root X2",
    # Amazon (AWS, CloudFront)
    "Amazon Root CA 1", "Amazon Root CA 2", "Amazon Root CA 3", "Amazon Root CA 4",
    # Google Trust Services (Google, YouTube, Cloudflare)
    "GTS Root R1", "GTS Root R3", "GTS Root R4",
    # DigiCert
    "DigiCert Global Root G2", "DigiCert Global Root G3",
    "DigiCert TLS RSA4096 Root G5", "DigiCert TLS ECC P384 Root G5",
    # Sectigo / USERTrust
    "USERTrust RSA Certification Authority", "USERTrust ECC Certification Authority",
    "Sectigo Public Server Authentication Root R46", "Sectigo Public Server Authentication Root E46",
    # Microsoft
    "Microsoft RSA Root Certificate Authority 2017", "Microsoft ECC Root Certificate Authority 2017",
    # GoDaddy / Starfield
    "Go Daddy Root Certificate Authority - G2", "Starfield Root Certificate Authority - G2",
    # GlobalSign
    "GlobalSign Root R46", "GlobalSign Root E46",
    # SSL.com (used by Cloudflare)
    "SSL.com Root Certification Authority RSA", "SSL.com Root Certification Authority ECC",
    # Certainly (Fastly)
    "Certainly Root R1", "Certainly Root E1",
]


# --- minimal DER reader/writer -------------------------------------------

def read_tlv(buf, i):
    """Return (tag_byte, value_start, value_end) for the TLV at buf[i]."""
    tag = buf[i]
    i += 1
    if tag & 0x1F == 0x1F:  # long-form tag number
        while buf[i] & 0x80:
            i += 1
        i += 1
    length = buf[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, i, i + length


def encode_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def renormalize(buf, start, end):
    """Re-encode the TLVs in buf[start:end], upper-casing PrintableStrings."""
    out = bytearray()
    i = start
    while i < end:
        tag, vs, ve = read_tlv(buf, i)
        if tag & 0x20:  # constructed: recurse
            inner = renormalize(buf, vs, ve)
        else:
            inner = bytes(buf[vs:ve])
            if tag == 0x13:  # PrintableString
                inner = inner.upper()
        out += bytes([tag]) + encode_len(len(inner)) + inner
        i = ve
    return bytes(out)


def ios_subject(der):
    """Subject content as stored in TrustStore.sqlite3 (inside the SEQUENCE)."""
    _, cs, _ = read_tlv(der, 0)          # Certificate SEQUENCE
    _, ts, te = read_tlv(der, cs)        # TBSCertificate SEQUENCE
    i = ts
    fields = []
    while i < te:
        tag, vs, ve = read_tlv(der, i)
        fields.append((tag, vs, ve))
        i = ve
    # [0] version (explicit, optional), serial, signature alg, issuer, validity, subject
    idx = 1 if fields[0][0] == 0xA0 else 0
    subject = fields[idx + 4]
    assert subject[0] == 0x30, "subject is not a SEQUENCE"
    return renormalize(der, subject[1], subject[2])


def validity(der):
    _, cs, _ = read_tlv(der, 0)
    _, ts, te = read_tlv(der, cs)
    i = ts
    fields = []
    while i < te:
        tag, vs, ve = read_tlv(der, i)
        fields.append((tag, vs, ve))
        i = ve
    idx = 1 if fields[0][0] == 0xA0 else 0
    _, vs, ve = fields[idx + 3]
    times = []
    j = vs
    while j < ve:
        tag, s, e = read_tlv(der, j)
        raw = der[s:e].decode()
        fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
        times.append(datetime.datetime.strptime(raw, fmt).replace(tzinfo=datetime.timezone.utc))
        j = e
    return times[0], times[1]


# --- main ------------------------------------------------------------------

def parse_bundle(text):
    """Map name -> DER. Each entry's DER must match Mozilla's listed SHA-256."""
    certs = {}
    pattern = r"\n([^\n#][^\n]*)\n=+\n((?:#[^\n]*\n)*)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)"
    for m in re.finditer(pattern, text, re.S):
        name, comments, pem = m.group(1).strip(), m.group(2), m.group(3)
        b64 = "".join(l for l in pem.splitlines() if "CERTIFICATE" not in l)
        der = base64.b64decode(b64)
        fp = re.search(r"Fingerprint \(SHA-256\): ([0-9A-F:]+)", comments)
        if fp and fp.group(1).replace(":", "") != hashlib.sha256(der).hexdigest().upper():
            sys.exit(f"fingerprint mismatch for {name}")
        certs[name] = der
    return certs


def main():
    bundle, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    text = bundle.read_text(encoding="utf-8")
    stamp = re.search(r"Certificate data from Mozilla as of: (.+)", text).group(1).strip()
    certs = parse_bundle(text)
    now = datetime.datetime.now(datetime.timezone.utc)

    missing = [n for n in ROOTS if n not in certs]
    if missing:
        sys.exit("not in bundle: " + ", ".join(missing))

    entries, md = [], []
    (outdir / "certs").mkdir(parents=True, exist_ok=True)
    for name in ROOTS:
        der = certs[name]
        nb, na = validity(der)
        if na <= now:
            sys.exit(f"{name} has expired")
        sha1 = hashlib.sha1(der).digest()
        entries.append({
            "name": name,
            "sha1": sha1,
            "sha256": hashlib.sha256(der).digest(),
            "subj": ios_subject(der),
            "data": der,
        })
        safe = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")
        (outdir / "certs" / f"{safe}.cer").write_bytes(der)
        md.append(f"| {name} | {na:%Y-%m-%d} | `{hashlib.sha256(der).hexdigest().upper()}` |")

    plist_path = outdir / "layout" / "Library" / "BensCertFix" / "roots.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_bytes(plistlib.dumps({"source": f"Mozilla CA bundle as of {stamp}", "roots": entries},
                                          fmt=plistlib.FMT_XML))

    (outdir / "ROOTS.md").write_text(
        "# Roots installed by Ben's Cert Fix\n\n"
        f"Taken from Mozilla's CA bundle (as of {stamp}), the same list Firefox and curl trust.\n\n"
        "| Root | Expires | SHA-256 fingerprint |\n|---|---|---|\n" + "\n".join(md) + "\n",
        encoding="utf-8")
    if len(sys.argv) > 3:
        site = Path(sys.argv[3])
        profile = write_profile(site / "assets" / "BensCertFix.mobileconfig", entries, stamp)
        write_site_page(site, entries, profile, stamp)

    print(f"{len(entries)} roots written ({stamp})")


def write_profile(path, entries, stamp):
    payloads = []
    for e in entries:
        safe = re.sub(r"[^A-Za-z0-9]+", "-", e["name"]).strip("-")
        payloads.append({
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"com.techieben.benscertfix.{safe}",
            "PayloadUUID": str(uuid.uuid5(PROFILE_NS, e["name"])).upper(),
            "PayloadDisplayName": e["name"],
            "PayloadCertificateFileName": f"{safe}.cer",
            "PayloadContent": e["data"],
        })
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.techieben.benscertfix",
        "PayloadUUID": str(uuid.uuid5(PROFILE_NS, "profile")).upper(),
        "PayloadDisplayName": "Ben's Cert Fix",
        "PayloadOrganization": "Ben's Cool Repos",
        "PayloadDescription": ("Adds up-to-date root certificates (Let's Encrypt, Amazon, Google, DigiCert "
                               "and more) so websites and apps can connect on older iOS. "
                               f"From Mozilla's CA list as of {stamp}."),
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payloads,
    }
    data = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


# GitHub Pages can't send the profile MIME type (it serves .mobileconfig as
# application/octet-stream, which iOS Safari won't install). So certfix.html
# carries the profile as a data: URI with the right type, plus each root as a
# .crt file, which Pages serves as application/x-x509-ca-cert.
PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ben's Cert Fix - Install</title>
<link rel="icon" href="CydiaIcon.png">
<style>
  body{{margin:0;background:#0b0f14;color:#e9f1f7;font-family:-apple-system,Helvetica,Arial,sans-serif;line-height:1.5}}
  .wrap{{max-width:720px;margin:0 auto;padding:28px 20px 60px}}
  a{{color:#1fd3ff}}
  h1{{font-size:28px;margin:.2em 0}}
  .sub{{color:#8aa0b3}}
  .btn{{display:block;text-align:center;font-weight:bold;font-size:17px;padding:15px 20px;border-radius:14px;
       text-decoration:none;background:#1fd3ff;color:#04222c;margin:18px 0 8px}}
  .box{{background:#121923;border:1px solid #223041;border-radius:14px;padding:16px 18px;margin:16px 0}}
  ol{{padding-left:22px}} li{{margin:6px 0}}
  ul.certs{{list-style:none;padding:0;margin:0}}
  ul.certs li{{border-top:1px solid #223041;padding:10px 0;margin:0}}
  ul.certs li:first-child{{border-top:0}}
  .key{{color:#7ff0b0;font-size:12px;margin-left:6px}}
</style>
</head>
<body>
<div class="wrap">
  <p><a href="./">&larr; Ben's Cool Repos</a></p>
  <h1>Ben's Cert Fix</h1>
  <p class="sub">Fixes "cannot connect" on websites and apps by adding the up-to-date certificates old iOS is missing.
  Open this page in <b>Safari</b> on the iPhone, iPod or iPad. Jailbroken? Install Ben's Cert Fix from Cydia instead.</p>

  <a class="btn" href="data:application/x-apple-aspen-config;base64,{profile_b64}">Install all {count} certificates</a>
  <div class="box">
    <ol>
      <li>Tap the button above and choose <b>Install</b>. iOS calls the profile "Unsigned"; that's normal for profiles that aren't from a company.</li>
      <li><b>iOS 10.3 only:</b> go to Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings and switch on the certificates.</li>
      <li>Close and reopen Safari or any app that couldn't connect.</li>
    </ol>
    <p class="sub">To remove it: Settings &rarr; General &rarr; Profiles &rarr; Ben's Cert Fix &rarr; Remove.</p>
  </div>

  <h2>Button didn't work? Install them one at a time</h2>
  <p class="sub">Tap a certificate, then Install. Start with the first one: it fixes the most sites.</p>
  <div class="box">
    <ul class="certs">
{links}
    </ul>
  </div>
  <p class="sub">From Mozilla's CA list as of {stamp}. Fingerprints:
  <a href="https://github.com/Bentechie123/benscoolrepos/blob/main/benscertfix/ROOTS.md">ROOTS.md</a>.</p>
</div>
</body>
</html>
"""

KEY_ROOTS = {"ISRG Root X1", "GTS Root R1", "Amazon Root CA 1", "DigiCert Global Root G2", "USERTrust RSA Certification Authority"}


def write_site_page(site, entries, profile, stamp):
    crt_dir = site / "assets" / "certs"
    crt_dir.mkdir(parents=True, exist_ok=True)
    for old in crt_dir.glob("*.crt"):
        old.unlink()
    # Most important first, then the rest in list order.
    ordered = [e for e in entries if e["name"] in KEY_ROOTS] + [e for e in entries if e["name"] not in KEY_ROOTS]
    links = []
    for e in ordered:
        safe = re.sub(r"[^A-Za-z0-9]+", "-", e["name"]).strip("-")
        (crt_dir / f"{safe}.crt").write_bytes(e["data"])
        tag = '<span class="key">most needed</span>' if e["name"] in KEY_ROOTS else ""
        links.append(f'      <li><a href="assets/certs/{safe}.crt">{e["name"]}</a>{tag}</li>')
    html = PAGE.format(profile_b64=base64.b64encode(profile).decode(), count=len(entries),
                       links="\n".join(links), stamp=stamp)
    (site / "certfix.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main()

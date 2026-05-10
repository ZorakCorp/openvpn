#! /usr/bin/python3
# Copyright (c) 2021 OpenVPN Inc <sales@openvpn.net>
# Copyright (c) 2021 Arne Schwabe <arne@rfc2549.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import os
from base64 import standard_b64decode

import pyotp

# Example script demonstrating how to use the auth-pending API in
# OpenVPN. This script is provided under MIT license to allow easy
# modification for other purposes.
#
# This needs support of crtext support on the client (e.g. OpenVPN for Android)
# See also the management-notes.txt file for more information about the auth pending
# protocol
#
# To use this script add the following lines in the openvpn config

# client-crresponse /path/to/totpauth.py
# auth-user-pass-verify /path/to/totpauth.py via-file
# auth-user-pass-optional
# auth-gen-token
#
# Prefer OPENVPN_TOTP_SECRETS_FILE (root:root 0600 recommended) containing:
#     # comments allowed
#     Test-Client=BASE32SHAREDSECRET...

# Note that this script does NOT verify username/password
# It is only meant for querying additional 2FA when certificates are
# used to authenticate


def _secrets_from_demo():
    sys.stderr.write(
        "WARNING: totpauth.py is using baked-in demonstration secrets "
        "(OPENVPN_TOTP_SECRETS_FILE not set).\nUse OPENVPN_TOTP_SECRETS_FILE "
        "in production.\n\n"
    )
    return {"Test-Client": "OS6JDNRK2BNUPQVX", "Client-2": "IXWEMP7SK2QWSHTG"}


def load_secrets():
    """
    Preferred: set OPENVPN_TOTP_SECRETS_FILE to a root-owned file readable only by
    the OpenVPN UID, with CN=BASE32SECRET lines (# for comments).

    Fallback: insecure demo secrets (see README).
    """
    path = os.environ.get("OPENVPN_TOTP_SECRETS_FILE")
    if not path:
        return _secrets_from_demo()
    secrets = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    sys.stderr.write(
                        f"{path}:{lineno}: line must be CN=SECRET, skipping\n"
                    )
                    continue
                cn, secret = line.split("=", 1)
                cn, secret = cn.strip(), secret.strip()
                if cn and secret:
                    secrets[cn] = secret
                else:
                    sys.stderr.write(f"{path}:{lineno}: empty CN or SECRET, skipping\n")
    except OSError as e:
        sys.stderr.write(f"Could not load OPENVPN_TOTP_SECRETS_FILE {path!r}: {e}\n")
        sys.exit(1)
    if not secrets:
        sys.stderr.write(f"No usable entries in secrets file {path!r}\n")
        sys.exit(1)
    return secrets


def main():
    # Get common name and script type from environment
    secrets = load_secrets()
    script_type = os.environ["script_type"]
    cn = os.environ["common_name"]

    if script_type == 'user-pass-verify':
        # signal text based challenge response
        if cn in secrets:
            extra = "CR_TEXT:E,R:Please enter your TOTP code!"
            write_auth_pending(300, 'crtext', extra)

            # Signal authentication being deferred
            sys.exit(2)
        else:
            # For unknown CN we report failure. Change to 0
            # to allow CNs without secret to auth without 2FA
            sys.exit(1)

    elif script_type == 'client-crresponse':
        response = None

        # Read the crresponse from the argument file
        # and convert it into text. A failure because of bad user
        # input (e.g. invalid base64) will make the script throw
        # an error and make OpenVPN return AUTH_FAILED
        with open(sys.argv[1], 'r') as crinput:
            response = crinput.read()
            response = standard_b64decode(response)
            response = response.decode().strip()

        if cn not in secrets:
            # Never succeed without a mapped secret once we expected a CR response.
            write_auth_control(0)
            return

        totp = pyotp.TOTP(secrets[cn])

        # Check if the code is valid (and also allow code +/-1)
        if totp.verify(response, valid_window=1):
            write_auth_control(1)
        else:
            write_auth_control(0)
    else:
        print(f"Unknown script type {script_type}")
        sys.exit(1)


def write_auth_control(status):
    with open(os.environ['auth_control_file'], 'w') as auth_control:
        auth_control.write("%d" % status)


def write_auth_pending(timeout, method, extra):
    with open(os.environ['auth_pending_file'], 'w') as auth_pending:
        auth_pending.write("%d\n%s\n%s" % (timeout, method, extra))


if __name__ == '__main__':
    main()

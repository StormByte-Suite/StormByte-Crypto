# Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
#
# This file is part of StormByte-Crypto.
#
# StormByte-Crypto original source is dual-licensed:
#
# 1. GNU Lesser General Public License v3.0 (or later)
#    You may redistribute and/or modify this file under the terms of the
#    GNU Lesser General Public License as published by the Free Software
#    Foundation, either version 3 of the License, or (at your option)
#    any later version.
#
# 2. Commercial license
#    Alternatively, this file may be used under the terms of a commercial
#    license agreement with the copyright holder
#    (David C. Manuelda <StormByte@gmail.com>).
#
# Both licenses apply only to original StormByte-Crypto source in this
# repository. They do not cover other StormByte modules or any third-party
# material shipped with this repository (including everything under
# thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
# tree and the StormByte suite it vendors), which remains under its own license.
#
# Neither license grants any patent rights. Any patent licenses required
# to use this software or third-party components must be obtained separately
# from the patent holders.
#
# StormByte-Crypto is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# version 3 along with StormByte-Crypto. If not, see
# <https://www.gnu.org/licenses/lgpl-3.0.html>.
#
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial

"""Regenerate public disposable certificate fixtures; run from the repository root.

Requires OpenSSL only at regeneration time. Keys exist only in subprocess pipes
and memory and are discarded; fixtures are not trusted identities. The test
target itself has no OpenSSL dependency. Dates/signatures change on regeneration.
"""

from pathlib import Path
import subprocess


def run(arguments, data=None):
	"""Run OpenSSL with optional pipe input, returning stdout or raising on failure."""
	return subprocess.run(
		["openssl", *arguments], input=data, stdout=subprocess.PIPE,
		stderr=subprocess.PIPE, check=True
	).stdout


server = "06082b06010505070301"
client = "06082b06010505070302"
any_usage = "0604551d2500"
unknown = "06032a0304"


def sequence(contents):
	"""Wrap short hex contents in a DER sequence for a fixture."""
	return "30" + f"{len(bytes.fromhex(contents)):02x}" + contents


fixtures = [
	("Absent", None, None),
	("Server", sequence(server), None),
	("Client", sequence(client), None),
	("Both", sequence(server + client), None),
	("BothCritical", sequence(server + client), "03020780"),
	("CA", sequence(server + client), "03020780"),
	("Unrelated", sequence(unknown), None),
	("Any", sequence(any_usage), None),
	("AnyCritical", sequence(any_usage), None),
	("AnyBoth", sequence(any_usage + server + client), None),
	("AnyServer", sequence(any_usage + server), None),
	("WrongAnyOid", sequence("06082b06010505070300"), None),
	("Repeated", sequence(server + server + client + client), None),
	("LargeUnknown", sequence("060c" + "ff" * 11 + "7f" + server + client), None),
	("UnknownThenBoth", sequence(unknown + server + client), None),
	("BothThenUnknown", sequence(server + client + unknown), None),
	("Empty", "3000", None),
	("TruncatedTag", "30", None),
	("WrongTag", "310a" + server, None),
	("NonOid", sequence(server + "0500"), None),
	("EmptyOid", sequence(server + "0600"), None),
	("UnterminatedOid", sequence(server + "06022a80"), None),
	("NonMinimalOid", sequence(server + "06032a8001"), None),
	("NonMinimalFirstArc", sequence(server + "06028001"), None),
	("UnterminatedFirstArc", sequence(server + "060181"), None),
	("Trailing", sequence(server) + "0500", None),
	("Truncated", "300b" + server, None),
	("NonMinimalLength", "30810a" + server, None),
	("Indefinite", "3080" + server + "0000", None),
	("ClientBadTail", sequence(client + "060181"), None),
	("BadCritical", sequence(server + client + "060181"), None),
	("BadHead", sequence("060181" + server + client), None),
	("Sign", None, "03020780"),
	("Encipher", None, "03020520"),
	("Agreement", None, "03020308"),
	("SignEncipher", sequence(server + client), "030205a0"),
	("SignAgreement", sequence(server + client), "03020388"),
	("SignDecipher", sequence(server + client), "0303078080"),
	("ZeroKU", None, "03020700"),
	("PaddingKU", None, "03020781"),
	("NonMinimalKU", None, "03020080"),
	("UndefinedKU", None, "0303068040"),
	("DeniedEKUBadKU", sequence(unknown), "03020781"),
	("BadEKUDeniedKU", "3000", "03020520"),
]

keys = {
	"EC": run(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
	"RSA": run(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
}
banner = Path("lib/public/StormByte/crypto/x509/certificate.hxx").read_text().split("#pragma once")[0]
output = [
	banner, "#pragma once\n\n#include <string_view>\n\n",
	"/**\n * @namespace PurposeFixtures\n * @brief Disposable self-signed public certificates generated by generate_purpose_fixtures.py.\n",
	" * @note Keys existed only in memory and pipes and were discarded. Raw DER extensions\n",
	" *       intentionally include malformed values; no trust or signature assertions are made.\n */\n",
	"namespace PurposeFixtures {\n",
]
for algorithm, key in keys.items():
	for name, eku, ku in fixtures:
		if algorithm == "RSA" and name not in ("Absent", "Both", "Sign", "Encipher", "Agreement"):
			continue
		command = [
			"req", "-new", "-x509", "-key", "/dev/stdin", "-sha256", "-days", "3650",
			"-subj", "/CN=purpose-fixture.invalid", "-set_serial", "1",
			"-addext", "basicConstraints=critical,CA:" + ("TRUE" if name == "CA" else "FALSE"),
		]
		if eku is not None:
			prefix = "critical," if name in ("BothCritical", "AnyCritical", "BadCritical") else ""
			command += ["-addext", f"2.5.29.37={prefix}DER:{eku}"]
		if ku is not None:
			command += ["-addext", f"2.5.29.15=DER:{ku}"]
		# A second extension of equal-length OID permits duplicate-extension tests
		# to change only its OID, leaving every enclosing DER length unchanged.
		if name == "Both":
			command += ["-addext", f"2.5.29.18=DER:{sequence(server + client)}"]
		pem = run(command, key).decode().strip()
		output += [
			f'\t/// {algorithm} certificate with the {name} extension profile.\n',
			f'\tconstexpr std::string_view {algorithm}_{name} = R"({pem})";\n\n',
		]
output.append("}\n")
Path("test/x509/purpose_fixtures.hxx").write_text("".join(output))

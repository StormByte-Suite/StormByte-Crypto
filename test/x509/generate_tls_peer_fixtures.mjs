/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

// Run from the repository root with node test/x509/generate_tls_peer_fixtures.mjs.
// Disposable keys stay in memory/subprocess pipes, never on disk.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const directory = 'test/x509/.peer-generation';
mkdirSync(directory);
const file = name => `${directory}/${name}`;
// Node's child stdin may be a socket; cat gives OpenSSL a reopenable POSIX pipe.
const openssl = (args, input) => execFileSync('bash',
	['-c', 'set -o pipefail; cat | openssl "$@"', 'openssl', ...args],
	{ input, stdio: ['pipe', 'pipe', 'pipe'] });
const fixtures = [];
const keys = new Map();
const certificateKeys = new Map();
let serial = 1;
const ca = 'basicConstraints=critical,CA:TRUE,pathlen:3\nkeyUsage=critical,keyCertSign,cRLSign';
const intermediate = 'basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign';
const leaf = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:peer.example.com,DNS:*.example.org,IP:192.0.2.1,IP:2001:db8::1';
const replace = (text, line, value) => text.split('\n').map(entry => entry.startsWith(`${line}=`) ? value : entry).filter(Boolean).join('\n');

function key(name, ...args) {
	keys.set(name, openssl(['genpkey', ...args]));
}

function cert(name, keyName, subject, issuer, extensions, days = 30, hash = '-sha256') {
	openssl(['req', '-new', '-key', '/dev/stdin', '-subj', `/CN=${subject}`, '-out', file(`${name}.csr`)], keys.get(keyName));
	writeFileSync(file(`${name}.cnf`), extensions);
	const signing = issuer
		? ['-CA', file(`${issuer}.pem`), '-CAkey', '/dev/stdin']
		: ['-signkey', '/dev/stdin'];
	openssl(['x509', '-req', '-in', file(`${name}.csr`), ...signing, '-set_serial', String(serial++),
		'-days', String(days), hash, '-extfile', file(`${name}.cnf`), '-out', file(`${name}.pem`)],
	keys.get(issuer ? certificateKeys.get(issuer) : keyName));
	certificateKeys.set(name, keyName);
	fixtures.push([name, readFileSync(file(`${name}.pem`), 'utf8')]);
}

try {
	for (const name of ['root', 'rogue', 'inter', 'sub', 'leaf'])
		key(name, '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1');
	key('rsa', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048');
	key('weak', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024');
	key('curve', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp256k1');
	key('curve384', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp384r1');
	key('curve521', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp521r1');
	key('rsaRoot', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048');
	key('rsaInter', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048');
	cert('Root', 'root', 'Peer Root', null, ca, 3650);
	cert('Rogue', 'rogue', 'Peer Root', null, ca, 3650);
	cert('RootShort', 'root', 'Peer Root', null, ca, 1);
	cert('RootPathZero', 'root', 'Peer Root', null, replace(ca, 'basicConstraints', 'basicConstraints=critical,CA:TRUE,pathlen:0'), 3650);
	cert('RootClient', 'root', 'Peer Root', null, `${ca}\nextendedKeyUsage=clientAuth`, 3650);
	cert('RootBadKU', 'root', 'Peer Root', null, replace(ca, 'keyUsage', 'keyUsage=critical,digitalSignature'), 3650);
	cert('RootNoKU', 'root', 'Peer Root', null, replace(ca, 'keyUsage', ''), 3650);
	cert('RootMalformedKU', 'root', 'Peer Root', null, replace(ca, 'keyUsage', '2.5.29.15=DER:03:02:00:04'), 3650);
	cert('RootSHA1', 'root', 'Peer Root', null, ca, 3650, '-sha1');
	cert('RootWeak', 'weak', 'Peer Root', null, ca, 3650);
	cert('RootNC', 'root', 'Peer Root', null, `${ca}\nnameConstraints=permitted;DNS:.example.com`, 3650);
	cert('RootBadEKU', 'root', 'Peer Root', null, `${ca}\n2.5.29.37=DER:30:00`, 3650);
	cert('RootNotCA', 'root', 'Peer Root', null, replace(ca, 'basicConstraints', 'basicConstraints=critical,CA:FALSE'), 3650);
	cert('Inter', 'inter', 'Peer Inter', 'Root', intermediate, 1000);
	cert('InterShort', 'inter', 'Peer Inter', 'Root', intermediate, 1);
	cert('RootRSA', 'rsaRoot', 'Peer Root RSA', null, ca, 3650);
	cert('InterRSA', 'rsaInter', 'Peer Inter RSA', 'RootRSA', intermediate, 1000);
	cert('Sub', 'sub', 'Peer Sub', 'Inter', replace(intermediate, 'basicConstraints', 'basicConstraints=critical,CA:TRUE,pathlen:0'), 100);
	cert('InterPathZero', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'basicConstraints', 'basicConstraints=critical,CA:TRUE,pathlen:0'), 1000);
	cert('InterNotCA', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'basicConstraints', 'basicConstraints=critical,CA:FALSE'), 1000);
	cert('InterNoBC', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'basicConstraints', ''), 1000);
	cert('InterNoncriticalBC', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'basicConstraints', 'basicConstraints=CA:TRUE,pathlen:1'), 1000);
	cert('InterBadKU', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'keyUsage', 'keyUsage=critical,digitalSignature'), 1000);
	cert('InterNoKU', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'keyUsage', ''), 1000);
	cert('InterBothCriticalEKU', 'inter', 'Peer Inter', 'Root', `${intermediate}\nextendedKeyUsage=critical,serverAuth,clientAuth`, 1000);
	cert('InterWeak', 'weak', 'Peer Inter', 'Root', intermediate, 1000);
	cert('InterMalformedKU', 'inter', 'Peer Inter', 'Root', replace(intermediate, 'keyUsage', '2.5.29.15=DER:03:02:00:04'), 1000);
	cert('InterClient', 'inter', 'Peer Inter', 'Root', `${intermediate}\nextendedKeyUsage=clientAuth`, 1000);
	cert('InterAny', 'inter', 'Peer Inter', 'Root', `${intermediate}\nextendedKeyUsage=anyExtendedKeyUsage`, 1000);
	cert('InterBadEKU', 'inter', 'Peer Inter', 'Root', `${intermediate}\n2.5.29.37=DER:30:00`, 1000);
	cert('InterBadSAN', 'inter', 'Peer Inter', 'Root', `${intermediate}\n2.5.29.17=DER:30:03:82:01:00`, 1000);
	cert('InterNC', 'inter', 'Peer Inter', 'Root', `${intermediate}\nnameConstraints=critical,permitted;DNS:.example.com`, 1000);
	cert('Leaf', 'leaf', 'peer.example.com', 'Inter', leaf);
	cert('LeafSub', 'leaf', 'peer.example.com', 'Sub', leaf);
	cert('LeafDirect', 'leaf', 'peer.example.com', 'Root', leaf);
	cert('LeafRSA', 'rsa', 'peer.example.com', 'Inter', leaf);
	for (const [name, hash] of [['LeafRSA256', '-sha256'], ['LeafRSA384', '-sha384'], ['LeafRSA512', '-sha512']])
		cert(name, 'rsa', 'peer.example.com', 'InterRSA', leaf, 30, hash);
	cert('LeafP384', 'curve384', 'peer.example.com', 'Inter', leaf, 30, '-sha384');
	cert('LeafP521', 'curve521', 'peer.example.com', 'Inter', leaf, 30, '-sha512');
	cert('LeafWeak', 'weak', 'peer.example.com', 'Inter', leaf);
	cert('LeafCurve', 'curve', 'peer.example.com', 'Inter', leaf);
	cert('LeafSHA1', 'leaf', 'peer.example.com', 'Inter', leaf, 30, '-sha1');
	cert('LeafServer', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'extendedKeyUsage', 'extendedKeyUsage=serverAuth'));
	cert('LeafBothCriticalEKU', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'extendedKeyUsage', 'extendedKeyUsage=critical,serverAuth,clientAuth'));
	cert('LeafClient', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'extendedKeyUsage', 'extendedKeyUsage=clientAuth'));
	cert('LeafNoUsage', 'leaf', 'peer.example.com', 'Inter', replace(replace(leaf, 'extendedKeyUsage', ''), 'keyUsage', ''));
	cert('LeafNoSAN', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'subjectAltName', ''));
	cert('LeafBadSAN', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'subjectAltName', '2.5.29.17=DER:30:03:82:01:00'));
	cert('LeafBadEKU', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'extendedKeyUsage', '2.5.29.37=DER:30:00'));
	cert('LeafBadKU', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'keyUsage', 'keyUsage=critical,keyEncipherment'));
	cert('LeafMalformedKU', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'keyUsage', '2.5.29.15=DER:03:02:00:80'));
	cert('LeafDecipher', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'keyUsage', 'keyUsage=digitalSignature,decipherOnly'));
	cert('LeafSignsCA', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'keyUsage', 'keyUsage=digitalSignature,keyCertSign'));
	cert('LeafCA', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'basicConstraints', 'basicConstraints=critical,CA:TRUE'));
	cert('LeafExplicitFalseBC', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'basicConstraints', '2.5.29.19=DER:30:03:01:01:00'));
	cert('LeafMalformedBC', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'basicConstraints', '2.5.29.19=DER:30:03:02:01:00'));
	cert('LeafCriticalSAN', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'subjectAltName', 'subjectAltName=critical,DNS:peer.example.com,IP:192.0.2.1'));
	cert('LeafCriticalURI', 'leaf', 'peer.example.com', 'Inter', replace(leaf, 'subjectAltName', 'subjectAltName=critical,DNS:peer.example.com,URI:https://example.com'));
	for (const [name, extension] of [
		['LeafUnknownCritical', '1.2.3.4=critical,DER:05:00'],
		['LeafBenign', '1.2.3.4=DER:05:00\ncertificatePolicies=1.2.3.4\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\ncrlDistributionPoints=URI:https://invalid.example/crl\nauthorityInfoAccess=OCSP;URI:https://invalid.example/ocsp'],
		['LeafCriticalSKI', 'subjectKeyIdentifier=critical,hash'],
		['LeafCriticalAKI', 'authorityKeyIdentifier=critical,keyid:always'],
		['LeafCriticalPolicies', 'certificatePolicies=critical,1.2.3.4'],
		['LeafNC', 'nameConstraints=permitted;DNS:.example.com'],
		['LeafPolicyMappings', '2.5.29.33=DER:30:00'],
		['LeafPolicyConstraints', 'policyConstraints=requireExplicitPolicy:0'],
		['LeafInhibitAnyPolicy', 'inhibitAnyPolicy=0'],
		['LeafTLSFeature', 'tlsfeature=status_request'],
		['LeafProxy', '1.3.6.1.5.5.7.1.14=DER:30:00']
	])
		cert(name, 'leaf', 'peer.example.com', 'Inter', `${leaf}\n${extension}`);
	const banner = readFileSync('lib/public/StormByte/crypto/x509/certificate.hxx', 'utf8').split('#pragma once')[0];
	writeFileSync('test/x509/tls_peer_fixtures.hxx', `${banner}#pragma once\n\n/**\n * @namespace TLSPeerFixtures\n * @brief Public OpenSSL fixtures; regenerated with generate_tls_peer_fixtures.mjs.\n * @note Disposable keys are deleted. No fixture is production trust material.\n */\nnamespace TLSPeerFixtures {\n${fixtures.map(([name, pem]) => `\t/// Public ${name} certificate.\n\tinline constexpr char ${name}[] = R"PEM(${pem})PEM";`).join('\n\n')}\n}\n`);
} finally {
	rmSync(directory, { recursive: true, force: true });
}

/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License v3.0 (or later).
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover third-party material.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

// Run from the repository root with node test/x509/generate_revocation_fixtures.mjs.
// OpenSSL and disposable private keys are used only during fixture generation.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const directory = mkdtempSync(join(tmpdir(), 'stormbyte-revocation-'));
const path = name => join(directory, name);

function openssl(...arguments_) {
	return execFileSync('openssl', arguments_, { stdio: ['ignore', 'pipe', 'pipe'] });
}

function write(name, contents) {
	writeFileSync(path(name), contents);
}

function certificate(name, serial, issuer = 'Root') {
	openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes',
		'-keyout', path(`${name}.key`), '-out', path(`${name}.csr`),
		'-subj', `/CN=${name}.revocation.test`);
	write(`${name}.ext`, [
		'basicConstraints=critical,CA:FALSE',
		'keyUsage=critical,digitalSignature',
		'extendedKeyUsage=serverAuth',
		`subjectAltName=DNS:${name}.revocation.test`,
		'authorityKeyIdentifier=keyid'
	].join('\n'));
	openssl('x509', '-req', '-in', path(`${name}.csr`),
		'-CA', path(`${issuer}.pem`), '-CAkey', path(`${issuer}.key`),
		'-set_serial', String(serial), '-days', '3650', '-sha256',
		'-extfile', path(`${name}.ext`), '-out', path(`${name}.pem`));
}

function makeRoot(name, commonName) {
	openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes',
		'-keyout', path(`${name}.key`), '-out', path(`${name}.pem`),
		'-subj', `/CN=${commonName}`, '-days', '3650', '-sha256',
		'-addext', 'basicConstraints=critical,CA:TRUE,pathlen:2',
		'-addext', 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature',
		'-addext', 'subjectKeyIdentifier=hash');
}

function writeBinary(name, bytes) {
	const hex = [...bytes].map(byte => `\\x${byte.toString(16).padStart(2, '0')}`);
	const lines = [];
	for (let index = 0; index < hex.length; index += 24)
		lines.push(`\t\t"${hex.slice(index, index + 24).join('')}"`);
	return `\tinline constexpr char ${name}[] =\n${lines.join('\n')};\n\n`;
}

function writeCertificate(name) {
	return `\tinline constexpr char ${name}[] = R"PEM(${readFileSync(path(`${name}.pem`), 'utf8').trim()})PEM";\n\n`;
}

function expirationDays() {
	const future = new Date(Date.now() + 3600 * 24 * 3600 * 1000);
	const year = String(future.getUTCFullYear() % 100).padStart(2, '0');
	return `${year}${String(future.getUTCMonth() + 1).padStart(2, '0')}${String(future.getUTCDate()).padStart(2, '0')}`
		+ `${String(future.getUTCHours()).padStart(2, '0')}${String(future.getUTCMinutes()).padStart(2, '0')}`
		+ `${String(future.getUTCSeconds()).padStart(2, '0')}Z`;
}

function currentTime() {
	return formattedTime(new Date());
}

function formattedTime(now) {
	const year = String(now.getUTCFullYear() % 100).padStart(2, '0');
	return `${year}${String(now.getUTCMonth() + 1).padStart(2, '0')}${String(now.getUTCDate()).padStart(2, '0')}`
		+ `${String(now.getUTCHours()).padStart(2, '0')}${String(now.getUTCMinutes()).padStart(2, '0')}`
		+ `${String(now.getUTCSeconds()).padStart(2, '0')}Z`;
}

try {
	makeRoot('Root', 'Revocation Test Root');
	makeRoot('OtherRoot', 'Different Revocation Root');
	certificate('Good', 1001);
	certificate('Revoked', 1002);
	certificate('Unknown', 1003);
	certificate('FutureRevoked', 1004);
	certificate('OtherIssuer', 2001, 'OtherRoot');
	certificate('OtherSameSerial', 1001, 'OtherRoot');

	openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes',
		'-keyout', path('Responder.key'), '-out', path('Responder.csr'),
		'-subj', '/CN=Authorized OCSP Responder');
	write('Responder.ext', [
		'basicConstraints=critical,CA:FALSE',
		'keyUsage=critical,digitalSignature',
		'extendedKeyUsage=critical,OCSPSigning',
		'1.3.6.1.5.5.7.48.1.5=DER:05:00',
		'authorityKeyIdentifier=keyid'
	].join('\n'));
	openssl('x509', '-req', '-in', path('Responder.csr'),
		'-CA', path('Root.pem'), '-CAkey', path('Root.key'),
		'-set_serial', '3001', '-days', '3650', '-sha256',
		'-extfile', path('Responder.ext'), '-out', path('Responder.pem'));
	openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes',
		'-keyout', path('BadResponder.key'), '-out', path('BadResponder.csr'),
		'-subj', '/CN=Unauthorized OCSP Responder');
	write('BadResponder.ext', [
		'basicConstraints=critical,CA:FALSE',
		'keyUsage=critical,digitalSignature',
		'extendedKeyUsage=critical,serverAuth',
		'authorityKeyIdentifier=keyid'
	].join('\n'));
	openssl('x509', '-req', '-in', path('BadResponder.csr'),
		'-CA', path('Root.pem'), '-CAkey', path('Root.key'),
		'-set_serial', '3002', '-days', '3650', '-sha256',
		'-extfile', path('BadResponder.ext'), '-out', path('BadResponder.pem'));

	const expiry = expirationDays();
	const revokedAt = currentTime();
	const futureRevokedAt = formattedTime(new Date(Date.now() + 24 * 3600 * 1000));
	write('index.txt', [
		`V\t${expiry}\t\t03E9\tunknown\t/CN=Good.revocation.test`,
		`R\t${expiry}\t${revokedAt},keyCompromise\t03EA\tunknown\t/CN=Revoked.revocation.test`,
		`R\t${expiry}\t${futureRevokedAt},keyCompromise\t03EC\tunknown\t/CN=FutureRevoked.revocation.test`
	].join('\n') + '\n');
	write('serial', '03EB\n');
	write('crlnumber', '01\n');
	write('ca.cnf', [
		'[ ca ]',
		'default_ca=CA_default',
		'[ CA_default ]',
		`database=${path('index.txt')}`,
		`new_certs_dir=${directory}`,
		`certificate=${path('Root.pem')}`,
		`private_key=${path('Root.key')}`,
		`serial=${path('serial')}`,
		`crlnumber=${path('crlnumber')}`,
		'default_md=sha256',
		'default_crl_days=2500',
		'policy=policy_any',
		'unique_subject=no',
		'crl_extensions=crl_ext',
		'[ policy_any ]',
		'commonName=supplied',
		'[ crl_ext ]',
		'authorityKeyIdentifier=keyid:always'
	].join('\n') + '\n');
	openssl('ca', '-gencrl', '-config', path('ca.cnf'), '-out', path('CRL.pem'));
	openssl('crl', '-in', path('CRL.pem'), '-outform', 'DER', '-out', path('CRL.der'));

	for (const name of ['Good', 'Revoked', 'Unknown', 'FutureRevoked']) {
		openssl('ocsp', '-index', path('index.txt'), '-rsigner', path('Root.pem'),
			'-rkey', path('Root.key'), '-CA', path('Root.pem'), '-issuer', path('Root.pem'),
			'-cert', path(`${name}.pem`), '-respout', path(`${name}.ocsp`), '-ndays', '2500', '-no_nonce');
	}
	openssl('ocsp', '-index', path('index.txt'), '-rsigner', path('Responder.pem'),
		'-rkey', path('Responder.key'), '-CA', path('Root.pem'), '-issuer', path('Root.pem'),
		'-cert', path('Good.pem'), '-respout', path('Delegated.ocsp'), '-ndays', '2500', '-no_nonce');
	openssl('ocsp', '-index', path('index.txt'), '-rsigner', path('BadResponder.pem'),
		'-rkey', path('BadResponder.key'), '-CA', path('Root.pem'), '-issuer', path('Root.pem'),
		'-cert', path('Good.pem'), '-respout', path('Unauthorized.ocsp'), '-ndays', '2500', '-no_nonce');
	openssl('ocsp', '-index', path('index.txt'), '-rsigner', path('Root.pem'),
		'-rkey', path('Root.key'), '-CA', path('Root.pem'), '-issuer', path('Root.pem'),
		'-cert', path('Good.pem'), '-respout', path('Nonce.ocsp'), '-ndays', '2500');
	write('other-index.txt',
		`V\t${expiry}\t\t03E9\tunknown\t/CN=OtherSameSerial.revocation.test\n`);
	openssl('ocsp', '-index', path('other-index.txt'), '-rsigner', path('OtherRoot.pem'),
		'-rkey', path('OtherRoot.key'), '-CA', path('OtherRoot.pem'), '-issuer', path('OtherRoot.pem'),
		'-cert', path('OtherSameSerial.pem'), '-respout', path('OtherIssuerSameSerial.ocsp'),
		'-ndays', '2500', '-no_nonce');

	const validationTime = Math.floor(Date.now() / 1000);
	const banner = readFileSync('lib/public/StormByte/crypto/x509/certificate.hxx', 'utf8')
		.split('#pragma once')[0];
	let output = `${banner}#pragma once\n\n#include <cstdint>\n#include <string_view>\n\n/**\n * @namespace RevocationFixtures\n`
		+ ' * @brief Public certificates and signed offline CRL/OCSP test responses.\n'
		+ ' * @note All private keys were generated in a temporary directory and discarded.\n'
		+ ' */\nnamespace RevocationFixtures {\n';
	output += `\tinline constexpr std::int64_t ValidationTime = ${validationTime};\n\n`;
	for (const name of ['Root', 'OtherRoot', 'Good', 'Revoked', 'Unknown',
		'OtherIssuer', 'OtherSameSerial', 'Responder', 'BadResponder'])
		output += writeCertificate(name);
	output += writeCertificate('FutureRevoked');
	output += writeBinary('CRL', readFileSync(path('CRL.der')));
	for (const name of ['Good', 'Revoked', 'Unknown', 'FutureRevoked'])
		output += writeBinary(`OCSP${name}`, readFileSync(path(`${name}.ocsp`)));
	output += writeBinary('OCSPDelegated', readFileSync(path('Delegated.ocsp')));
	output += writeBinary('OCSPUnauthorized', readFileSync(path('Unauthorized.ocsp')));
	output += writeBinary('OCSPNonce', readFileSync(path('Nonce.ocsp')));
	output += writeBinary('OCSPOtherIssuerSameSerial', readFileSync(path('OtherIssuerSameSerial.ocsp')));
	output += '}\n';
	writeFileSync('test/x509/revocation_fixtures.hxx', output);
} finally {
	rmSync(directory, { recursive: true, force: true });
}

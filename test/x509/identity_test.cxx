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
 */

#include <StormByte/crypto/x509/certificate.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/test_handlers.h>

#include <array>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

using namespace StormByte::Crypto;
using StormByte::Crypto::X509::Certificate;
using StormByte::Crypto::X509::IdentityError;
using StormByte::Crypto::X509::SubjectAltName;
using StormByte::Crypto::X509::SubjectAltNameType;

/*
 * Fixtures are self-signed P-256 certificates generated once with OpenSSL.
 * Their private keys were discarded at generation time, so none exists in the tree.
 * Pem_Valid carries a SAN of DNS, wildcard, mixed-case, A-label, IPv4, IPv6, email and URI
 * entries and a CN that matches no SAN. The remaining certificates carry one raw-DER
 * subjectAltName each, with the first entry "example.com" followed by the defect named
 * after the fixture. Pem_DupBase carries issuerAltName, patched in the test into a second
 * subjectAltName to exercise duplicate extension rejection.
 */
namespace {
	/// Self-signed fixture certificate "Valid".
	constexpr std::string_view Pem_Valid = R"(-----BEGIN CERTIFICATE-----
MIICOjCCAeGgAwIBAgIUDYwEaP/blL15uC8UNGT6mxPWedgwCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXY24tb25seS5leGFtcGxlLmludmFsaWQwIBcNMjYxMDMxMDg0
NzUyWhgPMjEyNjEwMDcwODQ3NTJaMCIxIDAeBgNVBAMMF2NuLW9ubHkuZXhhbXBs
ZS5pbnZhbGlkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGibIIXrc4O6EwXnN
Uy5sI2Ji2Bdc3zk73DUOVZsrGSFDbOAZw+zkarTkkEyhWOWwF6LPaJLETPlw+e/A
uXGiLKOB8jCB7zAdBgNVHQ4EFgQUNtcem0twwpyKC/hEBa5nOF8zdDUwHwYDVR0j
BBgwFoAUNtcem0twwpyKC/hEBa5nOF8zdDUwDwYDVR0TAQH/BAUwAwEB/zCBmwYD
VR0RBIGTMIGQggtleGFtcGxlLmNvbYISKi53aWxkLmV4YW1wbGUub3JnghVXV1cu
TWl4ZWQuRXhhbXBsZS5ORVSCFXhuLS1iY2hlci1rdmEuZXhhbXBsZYcEwAACCocQ
IAENuAAAAAAAAAAAAAAAAYENYUBleGFtcGxlLmNvbYYYaHR0cHM6Ly91cmkuZXhh
bXBsZS5jb20vMAoGCCqGSM49BAMCA0cAMEQCIEgvaV3FIM1UA0kshNm+y5HZIYFz
EKxQOAyHreI667GRAiBzmVLZ0EAabzy4NFvp0CwgYyKKgYxHpvj8QbdWkBQrgg==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "NoSan".
	constexpr std::string_view Pem_NoSan = R"(-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUbAhDkws/kEzFKuTHWIarJJppe+0wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS6sT6xmn7wYpaP6sdov7UppkHKUD4AnVBuRpIj
/PJtw6ByPRdt8+nfPpfCw2IuHQMnuJaFW5SECOipbYD0mcWOo1MwUTAdBgNVHQ4E
FgQUus3WGu5Z96T3alipwv2bwLtyRpkwHwYDVR0jBBgwFoAUus3WGu5Z96T3alip
wv2bwLtyRpkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBfM29y
DXsHvb8QYRUh/MbHB1OzyYn0sSt1VXEBKWhVEQIhANdpT/PQaO57Q86njsO0rBpL
gUmNYN2nhPTKrnLbutqY
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "IpLength5".
	constexpr std::string_view Pem_IpLength5 = R"(-----BEGIN CERTIFICATE-----
MIIBqjCCAVCgAwIBAgIUTOhUDiNbyq+W2mI/0UimXFo0cYowCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQE+PD/uzOsUNP+lE4vYm8pGj24vKMHr7+As+Ks
yuLKMmdKW+hIT182VA9yBYo+7i4/miiy5eIcFRcFdWiDNUiEo3IwcDAdBgNVHQ4E
FgQUCaJ/yJN0mHSlV2CY+tXx7efT8ZkwHwYDVR0jBBgwFoAUCaJ/yJN0mHSlV2CY
+tXx7efT8ZkwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHREEFjAUggtleGFtcGxlLmNv
bYcFAQIDBAUwCgYIKoZIzj0EAwIDSAAwRQIgA7oudmm+CYCnYvy+x06RUmWEYnb1
nBQTTSE7gAa9eygCIQDxAQAi+bsitO3w2DjXUTJbEiX6jUI+eig9D8UEPRVnvw==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "NulDns".
	constexpr std::string_view Pem_NulDns = R"(-----BEGIN CERTIFICATE-----
MIIBtTCCAVugAwIBAgIURbf/7WRe1ZQtEVFroyRSO4fV4UYwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ7ni8413Vkmtc6K6lQ2OJXEWITU9rfHWuJRsnC
RwDRkre7M8AEkFx0wQc8an6JQd7ZckuCBFgl/8/HdDK7/MUso30wezAdBgNVHQ4E
FgQUxY2t9NTcNoDbeIf+CoaJJPOAtEAwHwYDVR0jBBgwFoAUxY2t9NTcNoDbeIf+
CoaJJPOAtEAwDwYDVR0TAQH/BAUwAwEB/zAoBgNVHREEITAfggtleGFtcGxlLmNv
bYIQYmFkAC5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiEAuZ6q3NmWAw82
msyl2i7TGRks63K5bxVZGUUtLHCUtfwCIDuNDDUtNQNEC84lZOJYSKDMc6OunXG5
V2fGXAAvQAmq
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "PartialWildcard".
	constexpr std::string_view Pem_PartialWildcard = R"(-----BEGIN CERTIFICATE-----
MIIBtDCCAVmgAwIBAgIUO06xqpW5m9CP/hsGLudK+Y9+zJAwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQd8EWlwBbfPDEfHqi0V+zRzmJqbRlO4CQ3nuM2
jdE0NCAPomblGpFKklbALd0V489MKlQJJ3JxGVxGtW23wT8/o3sweTAdBgNVHQ4E
FgQUqIuF3mWQtOApcyvOMRf+KjBFO7gwHwYDVR0jBBgwFoAUqIuF3mWQtOApcyvO
MRf+KjBFO7gwDwYDVR0TAQH/BAUwAwEB/zAmBgNVHREEHzAdggtleGFtcGxlLmNv
bYIOYSouZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSQAwRgIhALgXzPntJA6Xf80R
Z1oZOGpBEnThNaUfrSjmvpCEwSdUAiEAug0LnkZ3mBY7VCW0OqDXNUiikKamqVHv
MgO2WBePxeQ=
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "DoubleWildcard".
	constexpr std::string_view Pem_DoubleWildcard = R"(-----BEGIN CERTIFICATE-----
MIIBtDCCAVqgAwIBAgIUBsD8YQqDIhDnS4yid1nXuw6OQi0wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ+/rSt89RUmsyp58Yltii+kjrQd8KXX6RLg7TO
vCgYNPMLQZ8TE1VsEEwU1PBafzlhq3PO50V4DagmjQE0XD15o3wwejAdBgNVHQ4E
FgQUo4QTedfta/xnUsi/2y7/uFZQCIwwHwYDVR0jBBgwFoAUo4QTedfta/xnUsi/
2y7/uFZQCIwwDwYDVR0TAQH/BAUwAwEB/zAnBgNVHREEIDAeggtleGFtcGxlLmNv
bYIPKi4qLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIQDhtmbJHKldxyZI
bSrdZKyAmv/kB6dB8yRCsnmqPwIqQAIgAM1sf8OPGZdCMY6/jYJ4Ej2gAuAKOKNj
5HCCJsuQFug=
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "WildcardPublicSuffix".
	constexpr std::string_view Pem_WildcardPublicSuffix = R"(-----BEGIN CERTIFICATE-----
MIIBqjCCAVCgAwIBAgIUCKA57ZM026bCx37YwnOrZcZwDGswCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS2gV5cRRTUu/LQPY9A1TNMytpsX/P/g2zRfUaT
qVZ/pkd/C3E/LWbIqOA+zL9ORPCQgbScIsjq+UZQQsjtxHv/o3IwcDAdBgNVHQ4E
FgQUDFuPHs1HY7bVzsDkE5x/nCGamoQwHwYDVR0jBBgwFoAUDFuPHs1HY7bVzsDk
E5x/nCGamoQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHREEFjAUggtleGFtcGxlLmNv
bYIFKi5jb20wCgYIKoZIzj0EAwIDSAAwRQIgTzZEZqqtN5xrM8YXEWpaT+00F7d/
DLFK1o6ax5TZkU4CIQDQoq0V7nl9tbUTjpw2kR32zaWo7rvRbIYtvEHE53cxAw==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "TrailingDotDns".
	constexpr std::string_view Pem_TrailingDotDns = R"(-----BEGIN CERTIFICATE-----
MIIBsTCCAVegAwIBAgIUSxnzjV4axNcr70Q7Agjh6Zb63+kwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARBNu9oYjuEbE564n8rxUpcTpvvpDz9p5uD85PQ
3Q4qSjRasK10lfaeInnij0Oyk/S/XCcr4N+RBr6OESOHnuT5o3kwdzAdBgNVHQ4E
FgQUPd9ZEn9DK7gX2SI+lfF7E3xBsJUwHwYDVR0jBBgwFoAUPd9ZEn9DK7gX2SI+
lfF7E3xBsJUwDwYDVR0TAQH/BAUwAwEB/zAkBgNVHREEHTAbggtleGFtcGxlLmNv
bYIMZXhhbXBsZS5jb20uMAoGCCqGSM49BAMCA0gAMEUCICweVyT40vq11fkPD4MX
a4Dw8VFVw0h3UVgz47J0UNGSAiEAwsr1SQ2mdb9DjHwTAkWZNgpZlohNhXNv+4yJ
2Y6ASqE=
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "EmptyDns".
	constexpr std::string_view Pem_EmptyDns = R"(-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUb5tbS5MctJl2j0X3U/j3AQeoUVgwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASUzI+fjiHgdmeHe3FcSL5Kcn6Zo2nnwrLxHZm+
BE7t7BfQpu0MoMVugFSnkB+a+LCMJsgaBT50rV3w1pt4qyWSo20wazAdBgNVHQ4E
FgQUd1YHeAJbrMEhasAcYtCcT7L6C4cwHwYDVR0jBBgwFoAUd1YHeAJbrMEhasAc
YtCcT7L6C4cwDwYDVR0TAQH/BAUwAwEB/zAYBgNVHREEETAPggtleGFtcGxlLmNv
bYIAMAoGCCqGSM49BAMCA0gAMEUCIENX+JqvPORijkMAMjPD1q/usxWASYtw2QKy
BhOaftP9AiEA2SPw8cVZVs+hL7Niv1/TdcMF6TmUGvpNJyDhz0JJWq4=
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "NonAsciiDns".
	constexpr std::string_view Pem_NonAsciiDns = R"(-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIUdwFKx5EvkjCXE5e+emdSQMkbGIQwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATCFELkgWko7aqmYy8Taesm+XJFDa72X8HqOgIB
I6P5INmzfmDanzWX+jdQq94uZpRRnXZS1ns6gJw1YEuGAUwgo34wfDAdBgNVHQ4E
FgQUyCJuZ0XWXxwG7NyXzzxdv21nGHYwHwYDVR0jBBgwFoAUyCJuZ0XWXxwG7NyX
zzxdv21nGHYwDwYDVR0TAQH/BAUwAwEB/zApBgNVHREEIjAgggtleGFtcGxlLmNv
bYIRY2Fmw6kuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAKTQZpeA3MBy
Ak3dV+5bWV7qB1JVx2LR5JanFdMkTBgAAiAsPIcv2lBSjG7lsl4DM1czlGr6o5BS
bNlYC7mNP9CihQ==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "UnknownTag".
	constexpr std::string_view Pem_UnknownTag = R"(-----BEGIN CERTIFICATE-----
MIIBpzCCAUygAwIBAgIUN5/KMdkPKSuTEA71ayqrXQ+DBRcwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQK3G+2jHL0GoOjWJGYyaZ3q3MWq5SehMx75qPs
DYFDUHEyIevZIl073NZYCSPxR1EHkkaax+JHhLxYSxCK4jigo24wbDAdBgNVHQ4E
FgQU7lzrMG0DUwWFC+n/AnYY5nYo180wHwYDVR0jBBgwFoAU7lzrMG0DUwWFC+n/
AnYY5nYo180wDwYDVR0TAQH/BAUwAwEB/zAZBgNVHREEEjAQggtleGFtcGxlLmNv
bYkBeDAKBggqhkjOPQQDAgNJADBGAiEA+tSsOfIeJCkD3iDSrviqufDci+tNo3xB
TymlhCucR4MCIQDooYu2ZsYVuQhaF4qgN8kOcpsRQLHS2aTvCM88jC2yXg==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "EmptySequence".
	constexpr std::string_view Pem_EmptySequence = R"(-----BEGIN CERTIFICATE-----
MIIBlzCCATygAwIBAgIUe+BKoTVANTsg5lh6mcKSpEQrMUIwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARJR9LSKgJCWvLFru4hPLn+XROsVuzDQ6U73M8o
5YgJl2BwVMSdYaeR1BUYpgQFXZAN8vMvsCwJnzPqdQTeb0QBo14wXDAdBgNVHQ4E
FgQUEGuiw31b4cHmuZvPqV0g7BlO+twwHwYDVR0jBBgwFoAUEGuiw31b4cHmuZvP
qV0g7BlO+twwDwYDVR0TAQH/BAUwAwEB/zAJBgNVHREEAjAAMAoGCCqGSM49BAMC
A0kAMEYCIQDbBtINw8XIZsHPEqUs6o0YPa+BpUNJrAMHLBobXZJg3AIhAKAsjMx2
/NeBQAM79gppBRwK8giVKkCO/vGO8FcZlErP
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "TruncatedEntry".
	constexpr std::string_view Pem_TruncatedEntry = R"(-----BEGIN CERTIFICATE-----
MIIBrzCCAVagAwIBAgIUf+aHlqBDN3KxuSsvmJzNFmYdND0wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATsTltFA2WiKlAKAl6RXAkw3GRKwr0FjBG2mBX8
s+U3WWIc3HiplB/8IBe0jLCKH4y6xTCikdqfG3tn7qssy7uTo3gwdjAdBgNVHQ4E
FgQUGRvNUeUbuUpErzFkN6+3qTfD3rIwHwYDVR0jBBgwFoAUGRvNUeUbuUpErzFk
N6+3qTfD3rIwDwYDVR0TAQH/BAUwAwEB/zAjBgNVHREEHDAaggtleGFtcGxlLmNv
bYIPZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDRwAwRAIgASWInwx7gvQGK/SODjl2
NzmKDY/R7nJb0BAM1rxVTk8CID40jibRzgMnJhyEjpmpR6zX9JJgfKdR+nDYgifQ
V+0p
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "TrailingBytes".
	constexpr std::string_view Pem_TrailingBytes = R"(-----BEGIN CERTIFICATE-----
MIIBpTCCAUqgAwIBAgIUJEuSSJHoZxFJ2SRCDgvkxijKPscwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATl/0ieISPI+sDwMKL51rGFS2E75bOkQFnf61oy
JV6xm0Rx8QmNykBhAn12HXWfIV26wHh9aWGu09BaL8LQ+FJSo2wwajAdBgNVHQ4E
FgQU38qRWwt1Aba5gvdAs6t6IFCBKIAwHwYDVR0jBBgwFoAU38qRWwt1Aba5gvdA
s6t6IFCBKIAwDwYDVR0TAQH/BAUwAwEB/zAXBgNVHREEEDAOggtleGFtcGxlLmNv
bQAwCgYIKoZIzj0EAwIDSQAwRgIhAIX/nfUvmy/aCgsW+/ZNdX8gO0YAEgabdoIH
p6eHbLSzAiEArrmFUOV/nJGqapX6lCM6MmOu6fPzs7zzopoJtRVBUuY=
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "EmailOnly".
	constexpr std::string_view Pem_EmailOnly = R"(-----BEGIN CERTIFICATE-----
MIIBpDCCAUugAwIBAgIUVA/PHcbDWAVxzR2eEB4IZaHi9l0wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATYqVncSPS8PFTcFDN3h/O8KFj7NEUDgZtdBsCz
BdhYr9bVPGR8vWsmNX9ifYtynZ8CPlUCXz/bpJYPFCE1i+Yoo20wazAdBgNVHQ4E
FgQUDD2bFQvHzU2hF+AnmbaOP2y9jeswHwYDVR0jBBgwFoAUDD2bFQvHzU2hF+An
mbaOP2y9jeswDwYDVR0TAQH/BAUwAwEB/zAYBgNVHREEETAPgQ1hQGV4YW1wbGUu
Y29tMAoGCCqGSM49BAMCA0cAMEQCIFMxcTP5yPqeH4mxMhN1bPysT4tJhT9yzCT+
Lau0il9uAiBY/rSLRL+CUIESM/lbsqVavwktub9qsVO0RmWUCHBBmw==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "Ipv6Length15".
	constexpr std::string_view Pem_Ipv6Length15 = R"(-----BEGIN CERTIFICATE-----
MIIBszCCAVqgAwIBAgIUOY1iinQDLpUG6lkVmF87mzRkiGkwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAzMTA4NDc1MloYDzIx
MjYxMDA3MDg0NzUyWjAaMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARBEC4r/tuFr1LN0MPZi7hHoxuNrGKBojYk3NfW
8EQW475reeKde3mdaIasVqJCDVUMHfUH0zoauYyRRWRLkEEPo3wwejAdBgNVHQ4E
FgQUy9BBjUGD7XLDrDkV0U6Qg7bfHFcwHwYDVR0jBBgwFoAUy9BBjUGD7XLDrDkV
0U6Qg7bfHFcwDwYDVR0TAQH/BAUwAwEB/zAnBgNVHREEIDAeggtleGFtcGxlLmNv
bYcPAAECAwQFBgcICQoLDA0OMAoGCCqGSM49BAMCA0cAMEQCIHO1uL1PGVYhJcsd
QRM9+yBm6D4VXs8Tx3vLYDovy7KZAiBNFhYsCwbC6oAzEJmMsUsybqSINkDUu97G
jlZP5u/wBg==
-----END CERTIFICATE-----)";

	/// Self-signed fixture certificate "DupBase".
	constexpr std::string_view Pem_DupBase = R"(-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIUJGM1E8sXcjQLf7vboHKjFMHJisMwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeC5leGFtcGxlLmNvbTAgFw0yNjEwMzEwODQ3NTJaGA8yMTI2
MTAwNzA4NDc1MlowGDEWMBQGA1UEAwwNeC5leGFtcGxlLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABI73ERrUzeYieGUEM2nn56GyAaLfZAQQ9JUqYw45+uDg
Gn92GtDuIhpMQPxWz6E2/FMm2PxMKiCuRnfgPDvFvSyjgYQwgYEwHQYDVR0OBBYE
FIcJgStpfauL9P8CUBlnFvWs38y7MB8GA1UdIwQYMBaAFIcJgStpfauL9P8CUBln
FvWs38y7MA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0RBA8wDYILZXhhbXBsZS5jb20w
FgYDVR0SBA8wDYILZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDRwAwRAIgfcBOn/IP
1OBkOVCDsujmFWqACaFcCApfabKwsNuzcyACIBOBT1CT7OVD9M5IecQ98I+pCkA/
IE15m0mcmollBJ7E
-----END CERTIFICATE-----)";

	/// Borrowed view of certificate or address bytes.
	using Bytes = std::span<const std::byte>;

	/**
	 * @brief Views text as bytes.
	 * @param text Text to view; it must outlive the result.
	 * @return Borrowed bytes of @p text.
	 */
	Bytes AsBytes(std::string_view text) {
		return Bytes(reinterpret_cast<const std::byte*>(text.data()), text.size());
	}

	/**
	 * @brief Copies literal address bytes into a binary array.
	 * @tparam N Address size in bytes.
	 * @param bytes Network-order address bytes.
	 * @return Array holding the same bytes.
	 */
	template<std::size_t N>
	std::array<std::byte, N> Address(const unsigned char (&bytes)[N]) {
		std::array<std::byte, N> result{};
		for (std::size_t i = 0; i < N; ++i)
			result[i] = static_cast<std::byte>(bytes[i]);
		return result;
	}

	/**
	 * @brief Loads a fixture certificate.
	 * @param pem PEM fixture text.
	 * @return Parsed certificate.
	 * @throws std::runtime_error The fixture does not load.
	 */
	Certificate Cert(std::string_view pem) {
		auto certificate = X509::Load(AsBytes(pem));
		if (!certificate)
			throw std::runtime_error("fixture failed to load");
		return *certificate;
	}

	/**
	 * @brief Tells whether an identity result failed with a given error.
	 * @param result Result to inspect.
	 * @param error Expected error.
	 * @return true when @p result holds @p error.
	 */
	bool Fails(const X509::ExpectedIdentity& result, IdentityError error) {
		return !result && *result.error() == error;
	}

	/**
	 * @brief Tells whether an extraction result failed with a given error.
	 * @param result Result to inspect.
	 * @param error Expected error.
	 * @return true when @p result holds @p error.
	 */
	bool Fails(const X509::ExpectedSubjectAltNames& result, IdentityError error) {
		return !result && *result.error() == error;
	}

	/**
	 * @brief Returns the shared valid fixture certificate.
	 * @return Parsed Pem_Valid.
	 */
	const Certificate& Valid() {
		static const Certificate certificate = Cert(Pem_Valid);
		return certificate;
	}

	/// Fixtures whose subjectAltName extension is structurally malformed.
	constexpr std::array<std::string_view, 12> MalformedPems = {
		Pem_IpLength5, Pem_Ipv6Length15, Pem_NulDns, Pem_PartialWildcard, Pem_DoubleWildcard,
		Pem_WildcardPublicSuffix, Pem_TrailingDotDns, Pem_EmptyDns, Pem_NonAsciiDns, Pem_UnknownTag,
		Pem_EmptySequence, Pem_TruncatedEntry
	};
}

// -------------------
// DNS
// -------------------
int test_dns_case_insensitive_exact() {
	const Certificate& cert = Valid();
	for (const std::string_view name : {"example.com", "EXAMPLE.COM", "Example.Com", "www.mixed.example.net",
		"WWW.MIXED.EXAMPLE.NET", "xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE"})
		ASSERT_TRUE(static_cast<bool>(cert.VerifyDNSName(name)));
	for (const std::string_view name : {"example.org", "badexample.com", "example.com.evil", "xexample.com",
		"mixed.example.net", "www.mixed.example.ne", "cn-only.example.invalid", "localhost"})
		ASSERT_TRUE(Fails(cert.VerifyDNSName(name), IdentityError::NoMatch));
	RETURN_TEST(0);
}

int test_dns_invalid_expected_names() {
	const Certificate& cert = Valid();
	const std::string long_label(64, 'a');
	std::string long_name;
	while (long_name.size() <= 253)
		long_name += "abcdefghi.";
	long_name += "com";
	const std::string nul_name("example\0.com", 12);
	for (const std::string_view name : {"", ".", "..", "example.com..", ".example.com", "a..example.com", "-a.example.com",
		"a-.example.com", "exa mple.com", "example.com/", "user@example.com", "example.com:443", "*.wild.example.org",
		"a*.example.com", "caf\xC3\xA9.example", "[::1]", "2001:db8::1", "192.0.2.10", "192.0.2.10.", "1.2.3.4", "example.123"}) {
		ASSERT_TRUE(Fails(cert.VerifyDNSName(name), IdentityError::InvalidExpectedName));
	}
	ASSERT_TRUE(Fails(cert.VerifyDNSName(nul_name), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(Fails(cert.VerifyDNSName(long_label + ".example.com"), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(Fails(cert.VerifyDNSName(long_name), IdentityError::InvalidExpectedName));
	RETURN_TEST(0);
}

int test_dns_no_common_name_fallback() {
	const Certificate no_san = Cert(Pem_NoSan);
	ASSERT_TRUE(static_cast<std::string_view>(no_san.SubjectCommonName()) == "www.example.com");
	ASSERT_TRUE(Fails(no_san.VerifyDNSName("www.example.com"), IdentityError::MissingSubjectAltName));
	ASSERT_TRUE(Fails(Valid().VerifyDNSName("cn-only.example.invalid"), IdentityError::NoMatch));
	const Certificate email_only = Cert(Pem_EmailOnly);
	ASSERT_TRUE(static_cast<std::string_view>(email_only.SubjectCommonName()) == "www.example.com");
	ASSERT_TRUE(Fails(email_only.VerifyDNSName("www.example.com"), IdentityError::NoMatch));
	RETURN_TEST(0);
}

int test_dns_not_matched_by_ip_entries() {
	ASSERT_TRUE(Fails(Valid().VerifyDNSName("192.0.2.10"), IdentityError::InvalidExpectedName));
	RETURN_TEST(0);
}

int test_dns_trailing_dot_is_normalized_once() {
	const Certificate& cert = Valid();
	ASSERT_TRUE(static_cast<bool>(cert.VerifyDNSName("example.com.")));
	ASSERT_TRUE(static_cast<bool>(cert.VerifyDNSName("A.Wild.Example.Org.")));
	ASSERT_TRUE(Fails(cert.VerifyDNSName("example.com.."), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(Fails(cert.VerifyDNSName("."), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(Fails(cert.VerifyDNSName("example.org."), IdentityError::NoMatch));
	RETURN_TEST(0);
}

int test_dns_wildcard_boundaries() {
	const Certificate& cert = Valid();
	for (const std::string_view name : {"a.wild.example.org", "A.WILD.EXAMPLE.ORG", "1.wild.example.org", "a-b.wild.example.org"})
		ASSERT_TRUE(static_cast<bool>(cert.VerifyDNSName(name)));
	for (const std::string_view name : {"wild.example.org", "a.b.wild.example.org", "example.org", "xwild.example.org",
		"a.wild.example.org.evil.com"})
		ASSERT_TRUE(Fails(cert.VerifyDNSName(name), IdentityError::NoMatch));
	ASSERT_TRUE(Fails(cert.VerifyDNSName(".wild.example.org"), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(Fails(cert.VerifyDNSName("*.wild.example.org"), IdentityError::InvalidExpectedName));
	RETURN_TEST(0);
}

// -------------------
// Extraction
// -------------------
int test_extract_missing_extension() {
	ASSERT_TRUE(Fails(Cert(Pem_NoSan).SubjectAltNames(), IdentityError::MissingSubjectAltName));
	RETURN_TEST(0);
}

int test_extract_supported_entries_in_order() {
	const auto names = Valid().SubjectAltNames();
	ASSERT_TRUE(static_cast<bool>(names));
	ASSERT_EQUAL(static_cast<std::size_t>(6), names->size());
	const std::array<std::string_view, 4> dns = {"example.com", "*.wild.example.org", "WWW.Mixed.Example.NET",
		"xn--bcher-kva.example"};
	for (std::size_t i = 0; i < dns.size(); ++i) {
		ASSERT_TRUE((*names)[i].Type() == SubjectAltNameType::DNS);
		ASSERT_TRUE(std::string_view(reinterpret_cast<const char*>((*names)[i].Value().data()), (*names)[i].Value().size()) == dns[i]);
	}
	ASSERT_TRUE((*names)[4].Type() == SubjectAltNameType::IP);
	ASSERT_EQUAL(static_cast<std::size_t>(4), static_cast<std::size_t>((*names)[4].Value().size()));
	ASSERT_TRUE((*names)[5].Type() == SubjectAltNameType::IP);
	ASSERT_EQUAL(static_cast<std::size_t>(16), static_cast<std::size_t>((*names)[5].Value().size()));
	const auto empty = Cert(Pem_EmailOnly).SubjectAltNames();
	ASSERT_TRUE(static_cast<bool>(empty));
	ASSERT_TRUE(empty->empty());
	RETURN_TEST(0);
}

// -------------------
// IP
// -------------------
int test_ip_exact_binary_match() {
	const Certificate& cert = Valid();
	const unsigned char v4[] = {192, 0, 2, 10};
	const unsigned char v6[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	ASSERT_TRUE(static_cast<bool>(cert.VerifyIPAddress(Address(v4))));
	ASSERT_TRUE(static_cast<bool>(cert.VerifyIPAddress(Address(v6))));
	RETURN_TEST(0);
}

int test_ip_mismatch_and_no_equivalence() {
	const Certificate& cert = Valid();
	const unsigned char other_v4[] = {192, 0, 2, 11};
	const unsigned char other_v6[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
	const unsigned char mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 10};
	const unsigned char ascii[] = {'1', '9', '2', '.'};
	ASSERT_TRUE(Fails(cert.VerifyIPAddress(Address(other_v4)), IdentityError::NoMatch));
	ASSERT_TRUE(Fails(cert.VerifyIPAddress(Address(other_v6)), IdentityError::NoMatch));
	ASSERT_TRUE(Fails(cert.VerifyIPAddress(Address(mapped)), IdentityError::NoMatch));
	ASSERT_TRUE(Fails(cert.VerifyIPAddress(Address(ascii)), IdentityError::NoMatch));
	RETURN_TEST(0);
}

int test_ip_no_san_and_no_ip_entries() {
	const unsigned char v4[] = {192, 0, 2, 10};
	ASSERT_TRUE(Fails(Cert(Pem_NoSan).VerifyIPAddress(Address(v4)), IdentityError::MissingSubjectAltName));
	ASSERT_TRUE(Fails(Cert(Pem_EmailOnly).VerifyIPAddress(Address(v4)), IdentityError::NoMatch));
	const unsigned char dns_bytes[] = {'e', 'x', 'a', 'm'};
	ASSERT_TRUE(Fails(Valid().VerifyIPAddress(Address(dns_bytes)), IdentityError::NoMatch));
	RETURN_TEST(0);
}

int test_ip_invalid_expected_size() {
	const std::array<std::byte, 17> bytes{};
	for (const std::size_t size : {0, 1, 3, 5, 15, 17})
		ASSERT_TRUE(Fails(Valid().VerifyIPAddress(Bytes(bytes.data(), size)), IdentityError::InvalidExpectedAddress));
	RETURN_TEST(0);
}

// -------------------
// Lifecycle
// -------------------
int test_lifecycle_values_outlive_certificate() {
	StormByte::Safe::Optional<SubjectAltName> retained;
	StormByte::Safe::Shared<IdentityError> retained_error;
	{
		const Certificate cert = Cert(Pem_Valid);
		const auto names = cert.SubjectAltNames();
		ASSERT_TRUE(static_cast<bool>(names));
		retained = names->front();
		auto failure = cert.VerifyDNSName("example.org");
		ASSERT_FALSE(static_cast<bool>(failure));
		retained_error = failure.error();
	}
	ASSERT_TRUE(retained.has_value());
	ASSERT_TRUE(retained->Type() == SubjectAltNameType::DNS);
	ASSERT_EQUAL(static_cast<std::size_t>(11), static_cast<std::size_t>(retained->Value().size()));
	ASSERT_TRUE(retained_error);
	ASSERT_TRUE(*retained_error == IdentityError::NoMatch);
	RETURN_TEST(0);
}

int test_lifecycle_copy_and_move() {
	Certificate original = Cert(Pem_Valid);
	Certificate copy = original;
	ASSERT_TRUE(static_cast<bool>(copy.VerifyDNSName("example.com")));
	Certificate moved = std::move(copy);
	ASSERT_TRUE(static_cast<bool>(moved.VerifyDNSName("example.com")));
	Certificate assigned;
	assigned = moved;
	ASSERT_TRUE(static_cast<bool>(assigned.VerifyDNSName("example.com")));
	ASSERT_TRUE(Fails(Certificate().VerifyDNSName("example.com"), IdentityError::MissingSubjectAltName));

	SubjectAltName entry(SubjectAltNameType::IP, StormByte::Safe::Binary(AsBytes("abcd")));
	SubjectAltName entry_copy(entry);
	SubjectAltName entry_moved(std::move(entry_copy));
	SubjectAltName entry_assigned;
	ASSERT_TRUE(entry_assigned.Type() == SubjectAltNameType::DNS);
	entry_assigned = entry_moved;
	ASSERT_TRUE(entry_assigned.Type() == SubjectAltNameType::IP);
	ASSERT_EQUAL(static_cast<std::size_t>(4), static_cast<std::size_t>(entry_assigned.Value().size()));
	RETURN_TEST(0);
}

// -------------------
// Malformed
// -------------------
int test_malformed_duplicate_extension_rejected_at_parse() {
	const Certificate base = Cert(Pem_DupBase);
	ASSERT_TRUE(static_cast<bool>(base.SubjectAltNames()));
	StormByte::Safe::Binary der = base.Der();
	const unsigned char issuer_alt_name_oid[] = {0x06, 0x03, 0x55, 0x1D, 0x12};
	std::size_t patched = 0;
	for (std::size_t i = 0; i + sizeof(issuer_alt_name_oid) <= static_cast<std::size_t>(der.size()); ++i) {
		bool same = true;
		for (std::size_t j = 0; j < sizeof(issuer_alt_name_oid) && same; ++j)
			same = der.span()[i + j] == static_cast<std::byte>(issuer_alt_name_oid[j]);
		if (same) {
			der[StormByte::ByteSize{i + 4}] = std::byte{0x11};
			++patched;
		}
	}
	ASSERT_EQUAL(static_cast<std::size_t>(1), patched);
	ASSERT_FALSE(X509::Load(der.span()).has_value());
	RETURN_TEST(0);
}

int test_malformed_entries_fail_even_with_match() {
	const unsigned char v4[] = {1, 2, 3, 4};
	for (const std::string_view pem : MalformedPems) {
		const Certificate cert = Cert(pem);
		ASSERT_TRUE(Fails(cert.SubjectAltNames(), IdentityError::MalformedSubjectAltName));
		ASSERT_TRUE(Fails(cert.VerifyDNSName("example.com"), IdentityError::MalformedSubjectAltName));
		ASSERT_TRUE(Fails(cert.VerifyDNSName("other.example"), IdentityError::MalformedSubjectAltName));
		ASSERT_TRUE(Fails(cert.VerifyIPAddress(Address(v4)), IdentityError::MalformedSubjectAltName));
	}
	ASSERT_TRUE(Fails(Cert(Pem_TrailingBytes).SubjectAltNames(), IdentityError::MalformedSubjectAltName));
	RETURN_TEST(0);
}

int test_malformed_expected_is_checked_before_certificate() {
	const Certificate cert = Cert(Pem_NulDns);
	ASSERT_TRUE(Fails(cert.VerifyDNSName(""), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(Fails(cert.VerifyIPAddress(Bytes{}), IdentityError::InvalidExpectedAddress));
	RETURN_TEST(0);
}

int main() {
	int result = 0;
	try {
		// -------------------
		// DNS
		// -------------------
		result += test_dns_case_insensitive_exact();
		result += test_dns_invalid_expected_names();
		result += test_dns_no_common_name_fallback();
		result += test_dns_not_matched_by_ip_entries();
		result += test_dns_trailing_dot_is_normalized_once();
		result += test_dns_wildcard_boundaries();

		// -------------------
		// Extraction
		// -------------------
		result += test_extract_missing_extension();
		result += test_extract_supported_entries_in_order();

		// -------------------
		// IP
		// -------------------
		result += test_ip_exact_binary_match();
		result += test_ip_invalid_expected_size();
		result += test_ip_mismatch_and_no_equivalence();
		result += test_ip_no_san_and_no_ip_entries();

		// -------------------
		// Lifecycle
		// -------------------
		result += test_lifecycle_copy_and_move();
		result += test_lifecycle_values_outlive_certificate();

		// -------------------
		// Malformed
		// -------------------
		result += test_malformed_duplicate_extension_rejected_at_parse();
		result += test_malformed_entries_fail_even_with_match();
		result += test_malformed_expected_is_checked_before_certificate();
	} catch (const std::exception& error) {
		std::cerr << "Unexpected exception: " << error.what() << std::endl;
		return 1;
	}
	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}

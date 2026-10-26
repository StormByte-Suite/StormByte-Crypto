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

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/x509/certificate.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/test_handlers.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace StormByte::Crypto;
using StormByte::Crypto::X509::Certificate;
using StormByte::Crypto::X509::KeyUsage;
using StormByte::Crypto::X509::TimePoint;

/*
 * Fixtures generated once with OpenSSL from throwaway keys:
 *   Root (RSA-2048, sha256WithRSA, self-signed, CA)
 *   └─ Intermediate (P-384, sha384WithRSA, CA pathlen:0)
 *      ├─ Leaf (P-384, ecdsa-with-SHA384, CA:FALSE, digitalSignature|keyAgreement)
 *      ├─ Leaf P-256 (ecdsa-with-SHA256)
 *      ├─ Window (valid 2025-01-01 .. 2030-01-01)
 *      ├─ Unknown critical extension
 *      └─ Sub CA (CA, no pathlen) └─ Deep leaf  → exceeds intermediate pathlen:0
 *   Other CA (P-384, unrelated sibling of Intermediate)
 *   No-CertSign CA (keyUsage digitalSignature only) └─ leaf
 *   Not-CA (CA:FALSE with keyCertSign) └─ leaf
 * Everything else is valid from 2020-01-01 to 9999-12-31.
 */
namespace {
	constexpr std::string_view Pem_root = R"(-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUEnuZguXQ4ufzmdCC52X9ge4QEdEwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5
OTkxMjMxMjM1OTU5WjAXMRUwEwYDVQQDDAxUZXN0IFJvb3QgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCW2iVKYQoDeSpLPhDRRJCmlLpvOerRwgzs
XPLqKTKWRnMXB+TutaRVw5nNtj+uT0yWxzJbj7p+3+yhtl9KwvexY465ApNFBP4Q
INKJbCmEcrS/Gk0kI49EN7W3gChn486MNtPN9DMLTzBvMeOjE3mPziwy8MnSy8sY
AQk48z7UbKDwF+sMf4lcIogmYHz9LqCIJb12EV+oq4Bpt3jwOc2uoWkKooPexi1G
yP3l3B9/yMXd3lZseC+uhg9JYgOc4vkxFMaxds02NCY7/k5iLTRqqDbQSt8kvl5d
uaXa+GKkmL1yGtqghJWC1xyUHSfbAJx2wPII7DRuouhCgyeILK8DAgMBAAGjYzBh
MB0GA1UdDgQWBBQz4RrBwx8aQqM3uwimn3g/1E2h/TAfBgNVHSMEGDAWgBQz4RrB
wx8aQqM3uwimn3g/1E2h/TAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjANBgkqhkiG9w0BAQsFAAOCAQEAXQ3MZWA65JRSlIuDVDBrMKRXi2Z2prcdfERE
GbPtQ4h/jB0hExNBB1ydUdgsNirkSVtbNNfqPWXqRlHiuoL3nFy8nzXVBDlsw/X4
LhDBh0WhRx3a5KxqN6yhh+JCoTL7ss32onhYBVNEEDKeEAGyaq7xeulKaSStWkcL
5hnXEFl8lLMpQoDi0SuR6vyawJn84Oke7gns6SOlpCa5WeUZoOjdRUeXdInmEu6z
G7afioq4UhSjArNPAXfw5KYClTt2YbIqoUn3YTDu48daWmBtMSIOrnbspvKcoYVR
u0m70xfo7T5WLj44blksEcaWDr2IUNwPFGfWFnB/r0tyR/Zlng==
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_int = R"(-----BEGIN CERTIFICATE-----
MIICcjCCAVqgAwIBAgIIEH1343cVq2MwDQYJKoZIhvcNAQEMBQAwFzEVMBMGA1UE
AwwMVGVzdCBSb290IENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5
WjAfMR0wGwYDVQQDDBRUZXN0IEludGVybWVkaWF0ZSBDQTB2MBAGByqGSM49AgEG
BSuBBAAiA2IABNF+yCrltxPStyCdXoLCh0JncdkXj/RyPyrzn/MHjaZkfnqS7p1O
pdGYsOpXNO24cCsMSDHVUOVPCM42zeLv5HfgeKXOuiyqH9FEWHC66R6RVDbIj0yb
gub+uF8IoiIbJaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFMiUnJbhYwJpQoGhc5AFJ+RbHik+MB8GA1UdIwQYMBaAFDPh
GsHDHxpCoze7CKafeD/UTaH9MA0GCSqGSIb3DQEBDAUAA4IBAQCLDSV5sKUTKZHH
xN3r9mkJx5bYtt5mRkZNbYcsQ1FrnORzrODMLVMTIAklKaa8i45ZyOhb9+7Wc7bf
qKcyHiiRW/JLRFY6Q12yrKq8wLtzueupKDU7zzDvzrCwjYzUdS+dwwlYalsWxAXr
m/Spa+Y9RGHonxP2VFKIBgGfgudFjV/PoQsF2fQO++3dWzJmS1Yk97XFEgvDmYRc
a1ODln1Wcto8UEZQyIUcmHG00BoMrBz6wNea58zMRXCkeQ/o4K5Z+Wkcd7c23hto
4/PKblPzkpulXlSuEA15rYFdX1b1T5dpSG4V/X65hxJVfhfw9/7R/sl7OGqb17XZ
rgI9WscC
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_leaf = R"(-----BEGIN CERTIFICATE-----
MIIB3jCCAWSgAwIBAgIJAPQnT9dAQnYbMAoGCCqGSM49BAMDMB8xHTAbBgNVBAMM
FFRlc3QgSW50ZXJtZWRpYXRlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5OTkxMjMx
MjM1OTU5WjAUMRIwEAYDVQQDDAlUZXN0IExlYWYwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQQqCZwoGF8z7Z8gKwbAMZHaSw6QoI2pHtN2J8r/j3g4VNDkXM+lVtl4Mb+
+JZOk+jR09wAul6gmDqejdSv4mUMpaUf0D4x0Ik1GIyS686qccgoFygJYxTo9Ofw
V3omXg+jdTBzMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgOIMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMB0GA1UdDgQWBBQEiLz8wm1v9BGz1kQ1HJWUR5nI5zAfBgNV
HSMEGDAWgBTIlJyW4WMCaUKBoXOQBSfkWx4pPjAKBggqhkjOPQQDAwNoADBlAjA8
TG7ie/1afqtlsNvb/4GYZxvVuIXeZV5xyZrht6ghYURK8Orr94CgyEqDvrP3Hy4C
MQD5dcjyLFl2fMWKTHes+ZfDYM1k52l+xtatLsN2XkZbOaqNq82VKDI4Eh+tZCpF
xoc=
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_leaf256 = R"(-----BEGIN CERTIFICATE-----
MIIByDCCAU2gAwIBAgIJALbxBd8gVr5IMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMM
FFRlc3QgSW50ZXJtZWRpYXRlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5OTkxMjMx
MjM1OTU5WjAaMRgwFgYDVQQDDA9UZXN0IExlYWYgUC0yNTYwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASwMHebgAiFW1UXxJj8P2IMGxclWCfsb/M5ZtH1uphQtQFU
w2ABYWgDJnRrsQbwxnd3ltNeS7q+OWFwg3ClX5Xxo3UwczAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIDiDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQU
7u/+G7o1NvXVMQSr6XVHkMvF09swHwYDVR0jBBgwFoAUyJScluFjAmlCgaFzkAUn
5FseKT4wCgYIKoZIzj0EAwIDaQAwZgIxAL9WqtxmCfiC6ZoHDffgd7B8jv7Oi9Nk
j28xV7izUGiaxeuFdLajsRI7x2wmozcZYQIxAKeTbMH+PkcjlD9qsOraVRvuKnsW
xNzsOj6L4+XATccWq19cIguw5gJlQHeQR3awLg==
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_window = R"(-----BEGIN CERTIFICATE-----
MIIB3jCCAWSgAwIBAgIJAPxW4aEd3v64MAoGCCqGSM49BAMDMB8xHTAbBgNVBAMM
FFRlc3QgSW50ZXJtZWRpYXRlIENBMB4XDTI1MDEwMTAwMDAwMFoXDTMwMDEwMTAw
MDAwMFowFjEUMBIGA1UEAwwLVGVzdCBXaW5kb3cwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATNeXBoW7Lb7Akmr/kfXQKisvsMmDuoBlf+uNIhTXw1p2A+DCzQu9Knxlbn
TG2uguI3XcCE6Uyx9LARy33FXpVVENyqwuT0D2hxNnxWivQsVKqeQZcRVskyIXW/
2fUXeBSjdTBzMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgOIMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMB0GA1UdDgQWBBTifN3fq9j5qVe7zjb067FYT9CIojAfBgNV
HSMEGDAWgBTIlJyW4WMCaUKBoXOQBSfkWx4pPjAKBggqhkjOPQQDAwNoADBlAjEA
qtUzeNsLFLCeucyOc2LUURn1lWqcUNcsuarKzsorFrE5/nOZ4uXSLu8T2S17HW9t
AjAaxdiAaRV9nu1hQtsBlKxkvkDxJCpFkc5Bc/hiDhRDvy5iSn4Y2Apf3RTLlRq+
QcE=
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_unknown = R"(-----BEGIN CERTIFICATE-----
MIIB6TCCAW+gAwIBAgIJAIBkRnPcwqAyMAoGCCqGSM49BAMDMB8xHTAbBgNVBAMM
FFRlc3QgSW50ZXJtZWRpYXRlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5OTkxMjMx
MjM1OTU5WjAgMR4wHAYDVQQDDBVUZXN0IFVua25vd24gQ3JpdGljYWwwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAQXB/8HZiMMumD7yvPxOR9n9mSpW9ioN+5Ech/WyXV7
2yFW7quhybLEVV8fvUxZYyAbQc9mBPOk3GU2urY8y3ViaGPSSya2BzuGOSuzCjgC
ARHiRfJ6/FXBbYu1jL9vknCjdDByMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
AgeAMBIGCSsGAQQBg7IDAQEB/wQCBQAwHQYDVR0OBBYEFD4z6HONeZlo4ngSRiFD
UdIk7LIDMB8GA1UdIwQYMBaAFMiUnJbhYwJpQoGhc5AFJ+RbHik+MAoGCCqGSM49
BAMDA2gAMGUCMQD5tJNsr6yIxG+lYZdwzXemYGUFDru7IdtXFvEF1eBbQLdPRthD
SUq/aE2iBHizPZoCMD5D70E6Ll58jyUKmVOmGgdgPoBPGWL9MejBLqGeiaJ6xPPE
y8tvh3Z666aF//JMQQ==
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_sub = R"(-----BEGIN CERTIFICATE-----
MIIBzjCCAVSgAwIBAgIJAOBDiNAHoUXVMAoGCCqGSM49BAMDMB8xHTAbBgNVBAMM
FFRlc3QgSW50ZXJtZWRpYXRlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5OTkxMjMx
MjM1OTU5WjAWMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABDcI0oc73RYb7qDnrwZZWF7d1H+/R/pmcV8qLOnN42l61fSWkph7kotn
9WRe9w2rbmgAulQOIF/ttXHp/kLkQGy8VwdLdDeLglm7bOIZdFRwUfZLFg6QuH96
5YIjDoXs76NjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0OBBYEFFAUWBGlIc+vzUA3z4nQQpRzAW7aMB8GA1UdIwQYMBaAFMiUnJbhYwJp
QoGhc5AFJ+RbHik+MAoGCCqGSM49BAMDA2gAMGUCMDrvLvw320+q4/q2OXfMHSBH
QiTLFNVmu1KXR6tD0x7m88VnmAqRn1HUfH8CFUk1EgIxAP6wmphhSRUJY1NzhZxO
DnQbrcxK1TCmfWhtaVs40PvX+IfDu7zmAB0bYdQULnnpDg==
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_deep = R"(-----BEGIN CERTIFICATE-----
MIIB2DCCAV+gAwIBAgIIcKNXsk9nTvAwCgYIKoZIzj0EAwMwFjEUMBIGA1UEAwwL
VGVzdCBTdWIgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMBkx
FzAVBgNVBAMMDlRlc3QgRGVlcCBMZWFmMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE
m2V5p/CPTUPxUJ0z+B462oeFEFelMp/ie3pDd0fa03gArFjEeTAqk6m+T4gchXK5
bZ7/uFezZM+KWM0pAodzpszk3Kcw9S/kGVnv4/jEHVqvQKKtGKSigjlMTUgpta2r
o3UwczAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDiDATBgNVHSUEDDAKBggr
BgEFBQcDATAdBgNVHQ4EFgQULx63f8r03MiygWlugb5kLcXvXOYwHwYDVR0jBBgw
FoAUUBRYEaUhz6/NQDfPidBClHMBbtowCgYIKoZIzj0EAwMDZwAwZAIwCf8TFs+1
sEFOmU88EqeernB7XMCu3SZuLwiuE3YMj+ZRgCRnmzfaHHfxylCfVrLQAjAllsVW
MudNTe80NbxkkLejf6eIeQo/oonSfC1UW69gnNIgFyDCSNuCFGWIkaLhtg0=
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_other = R"(-----BEGIN CERTIFICATE-----
MIICbDCCAVSgAwIBAgIJAOKbwRHr85WbMA0GCSqGSIb3DQEBDAUAMBcxFTATBgNV
BAMMDFRlc3QgUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1
OVowGDEWMBQGA1UEAwwNVGVzdCBPdGhlciBDQTB2MBAGByqGSM49AgEGBSuBBAAi
A2IABEFN/F8dLNiBl9lftCYvH0ytuE36SclHnxORjHyMgECo88cBRCfCBZscvhsq
ZH5S2v53K8pryOSIrIOaldhaTWuubAUKM2XkWpuEehdB0JMdo4XRivAVOeil5A4Z
ivKmnqNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0OBBYEFD5sf4KWfzillB7MnBYpB2vzL+O+MB8GA1UdIwQYMBaAFDPhGsHDHxpC
oze7CKafeD/UTaH9MA0GCSqGSIb3DQEBDAUAA4IBAQAwapQUjTJG3JvPegNkQ0Uo
wTPXXYWQckbkZAlanO5QP9ZiqzQSp2ykXnVYjTIVCeQ+oUq4OvNFWiOwBa7lOvs7
+CWvhKQwrbbHpaeKiRvfQTKBzJGwylb/qXzR+mgOdceTYsF0Tq+lX4nFi8otToiQ
IrsdsQgmyOt7SPXuTKm8N+CyJvQXOIn1zUFikSynFWprGm6ySBlaVXaBjzy0jlGW
dhMUnNHgufdyBgVdJl5BA3nH6f7acAao/SA0tQOpPXxvFrge790gMgrlebQF7yQj
KfkY8Ua9rLdXbVehjOy008i33j2hZ6x6gifba8HTeYYqKKqgu+w8ozj5hL3OrnKx
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_nocs = R"(-----BEGIN CERTIFICATE-----
MIICbzCCAVegAwIBAgIJAKlb+tEBj5v7MA0GCSqGSIb3DQEBDAUAMBcxFTATBgNV
BAMMDFRlc3QgUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1
OVowHjEcMBoGA1UEAwwTVGVzdCBObyBDZXJ0U2lnbiBDQTB2MBAGByqGSM49AgEG
BSuBBAAiA2IABEO2uGDReABeKQuipoJc6W36w9Ers4XF7HCiYqYkWJNVi+VS7PpC
UPHA5ER4r8xB9Vz2w1kmtl9ICLsvSJi8r3O8H/iKaQg0fDGYmFv9WVWj3KsugCH+
8ktKixVK5Z/SvqNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCB4Aw
HQYDVR0OBBYEFFScOZePCwQxaiWEBMlUuRC36nU9MB8GA1UdIwQYMBaAFDPhGsHD
HxpCoze7CKafeD/UTaH9MA0GCSqGSIb3DQEBDAUAA4IBAQCJdYfE/K1pyjPHC4d7
PLD6Hsqs6X+lvl+LxrP6h7filDRz7aoXQPhq7BcITqBISZMo5YlCxaS2bF84YeNe
Gk+/DKiCz0GUkKVL03UEkgMNAY2XUoG5cg65ZZeZeHvIessqtWgViwAJuUYGyfx4
5v1BV63QViz+39tbmN9i6nBoBlSKuKB7uWR7cmZkuG4ilXEEKKsZXFHzS3MPLwrv
w9Veaea3i1eBPaSDunxfgh1eTjEjGjNCCl2S8Kjdwk91UOhZr9YIVgnsNA90zXrS
GtUBKZTbndJAI3UaZXN0+VzjzIT8jF0Dvhw6+3vSVwLAcafYpWrGhKrwstlwSNih
A2vF
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_nocsleaf = R"(-----BEGIN CERTIFICATE-----
MIIB6TCCAW+gAwIBAgIJAIduA0Ftj+lDMAoGCCqGSM49BAMDMB4xHDAaBgNVBAMM
E1Rlc3QgTm8gQ2VydFNpZ24gQ0EwIBcNMjAwMTAxMDAwMDAwWhgPOTk5OTEyMzEy
MzU5NTlaMCAxHjAcBgNVBAMMFVRlc3QgTm8gQ2VydFNpZ24gTGVhZjB2MBAGByqG
SM49AgEGBSuBBAAiA2IABB6ZNnUHUB/jYUKSzQzgQCXq7IPHLznkerj7j3Gg8qdd
HreUwCB5sQLo2Bz5TYuiBLBZ4T/kQQmTPmIgI0hDOnM7ZZIz7S2DFiXM2h4OiPTz
JhVSMVYmEcn+o4EjK2f7TqN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC
A4gwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFCAFDQLbPi5KjFdNr8yP
kmoPPxorMB8GA1UdIwQYMBaAFFScOZePCwQxaiWEBMlUuRC36nU9MAoGCCqGSM49
BAMDA2gAMGUCMQDBsvmM9SK5w6gMdQLiyJ7Fv93ojnJ/1IEBWPlxgR8KiKmAIgcT
18JNqdDILzt+BvcCME502MU0OMI00Q6w24LG3q31gZNNu7PFw36Hf55LtoVCoIRJ
RB6QxdoutBS7xN192Q==
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_notca = R"(-----BEGIN CERTIFICATE-----
MIICZDCCAUygAwIBAgIJAOM9YyEZL5aqMA0GCSqGSIb3DQEBDAUAMBcxFTATBgNV
BAMMDFRlc3QgUm9vdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1
OVowFjEUMBIGA1UEAwwLVGVzdCBOb3QgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAQ4pzFcLAsj2bHNq2cj0Y4S16uFOtxkkZ8QkhdyKELLqU55xDwwldaFJTWhFduR
QpljNqR5Egipu9eqw07KQInzB1TmUd9lONLX2QfaTaMJOuhh9UjZIUFrErefhiCd
yZOjYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgKEMB0GA1UdDgQWBBRf
9dqBOLlJPIAzq3jMtXrzmTCzgDAfBgNVHSMEGDAWgBQz4RrBwx8aQqM3uwimn3g/
1E2h/TANBgkqhkiG9w0BAQwFAAOCAQEAbJrWWwJbuMCm5hKJlgUhIn23V5tGZdde
zFoBUXmyWhC4lQ2y7fql7uFKux6IYru6GJ181Al9XKU+7Uf5nD2uWfXY/spSpMUW
MXkU9bu3IpP7GKMYDCTYbfBdhG8QPf0BQKxXvOuJlKb8tfB9jk4lz0a6kK02IGl/
J6ojbmNpv6myyc1i64IOqlRCxxK6kiFjw3a+DRudSwNSKOyFXQdzz5zMtx2Hc+UF
GECcHBitpV/Wnqzl5WwE8GgqX6vdLg3Xo1mDkfhOFNyPX312f5wES+qMRs0RYoYd
+ucVh9gsr7apn3Io1sUJMxDjpYG58+DOz2KedEHukail99QbXJNr7Q==
-----END CERTIFICATE-----
)";

	constexpr std::string_view Pem_notcaleaf = R"(-----BEGIN CERTIFICATE-----
MIIB3DCCAWKgAwIBAgIJAKvreE26mhZGMAoGCCqGSM49BAMDMBYxFDASBgNVBAMM
C1Rlc3QgTm90IENBMCAXDTIwMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAb
MRkwFwYDVQQDDBBUZXN0IE5vdCBDQSBMZWFmMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEg3y0pyp1pmnYlcpwq71TWlBa+ZKx3pYIU+z4Zp1worVQaQ9+xZ/gEOlL0S9w
Ci6yZemS38J2zM+h7yWBgZI3unNPPlKZyxMrW06BARoQs+6tg6IV79Yp+P2/9B/X
/Euto3UwczAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDiDATBgNVHSUEDDAK
BggrBgEFBQcDATAdBgNVHQ4EFgQUWz1Md5wy3DiWWhOJ6SM48tmXEQ4wHwYDVR0j
BBgwFoAUX/XagTi5STyAM6t4zLV685kws4AwCgYIKoZIzj0EAwMDaAAwZQIxAK0P
N2lNUx45yPn7StWbPhIKZDCRH0tcrfx+uTGuAzQSovWSEk9g6jTb0ifidpyeXwIw
VqAYhKU4+PeUIMPoY8bx2O7IiPpY/4v9igk3uoLfjt8o+LYxLtRtGk8gEz5HKKcH
-----END CERTIFICATE-----
)";

	std::span<const std::byte> Bytes(std::string_view text) {
		return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
	}

	Certificate Cert(std::string_view pem) {
		auto certificate = X509::Load(Bytes(pem));
		if (!certificate)
			throw std::runtime_error("fixture failed to load");
		return *certificate;
	}

	TimePoint Date(int year, unsigned month, unsigned day) {
		return TimePoint{std::chrono::sys_days{std::chrono::year{year} / month / day}};
	}

	const TimePoint Now = Date(2026, 10, 26);
}

int test_parse_fields() {
	const Certificate leaf = Cert(Pem_leaf);
	ASSERT_EQUAL(leaf.Version(), 3u);
	ASSERT_TRUE(static_cast<std::string_view>(leaf.SubjectCommonName()) == "Test Leaf");
	ASSERT_TRUE(static_cast<std::string_view>(leaf.IssuerCommonName()) == "Test Intermediate CA");
	ASSERT_FALSE(leaf.IsCA());
	ASSERT_TRUE(leaf.HasKeyUsage(KeyUsage::DigitalSignature));
	ASSERT_TRUE(leaf.HasKeyUsage(KeyUsage::KeyAgreement));
	ASSERT_FALSE(leaf.HasKeyUsage(KeyUsage::KeyCertSign));
	ASSERT_EQUAL(static_cast<std::size_t>(leaf.SerialNumber().size()), 8u + (static_cast<unsigned>(leaf.SerialNumber()[StormByte::ByteSize{0}]) == 0 ? 1u : 0u));
	ASSERT_TRUE(leaf.NotBefore() == Date(2020, 1, 1));
	ASSERT_TRUE(leaf.NotAfter() == Date(9999, 12, 31) + std::chrono::hours(23) + std::chrono::minutes(59) + std::chrono::seconds(59));

	const Certificate intermediate = Cert(Pem_int);
	ASSERT_TRUE(intermediate.IsCA());
	const auto path_length = intermediate.PathLength();
	ASSERT_TRUE(path_length.has_value());
	ASSERT_EQUAL(*path_length, 0u);
	ASSERT_TRUE(intermediate.HasKeyUsage(KeyUsage::KeyCertSign));
	ASSERT_TRUE(intermediate.HasKeyUsage(KeyUsage::CRLSign));
	ASSERT_FALSE(intermediate.HasKeyUsage(KeyUsage::DigitalSignature));

	const Certificate root = Cert(Pem_root);
	ASSERT_TRUE(root.IsCA());
	ASSERT_FALSE(root.PathLength().has_value());
	return 0;
}

int test_public_key() {
	auto key = Cert(Pem_leaf).PublicKey();
	ASSERT_TRUE(static_cast<bool>(key));
	ASSERT_TRUE(key->Type() == KeyPair::Type::ECC);
	ASSERT_FALSE(key->PrivateKey().has_value());
	auto rsa = Cert(Pem_root).PublicKey();
	ASSERT_TRUE(static_cast<bool>(rsa));
	ASSERT_TRUE(rsa->Type() == KeyPair::Type::RSA);
	return 0;
}

int test_save_roundtrip() {
	const Certificate leaf = Cert(Pem_leaf);
	const auto der = leaf.Save(KeyPair::StorageFormat::DER);
	ASSERT_TRUE(der == leaf.Der());
	auto from_der = X509::Load(der.span());
	ASSERT_TRUE(from_der.has_value());
	ASSERT_TRUE(*from_der == leaf);
	const auto pem = leaf.Save();
	const std::string_view text(reinterpret_cast<const char*>(pem.data()), static_cast<std::size_t>(pem.size()));
	ASSERT_TRUE(text == Pem_leaf);
	return 0;
}

int test_load_all_bundle() {
	std::string bundle = "comment line\n";
	bundle.append(Pem_leaf).append(Pem_int).append(Pem_root);
	auto all = X509::LoadAll(Bytes(bundle));
	ASSERT_EQUAL(all.size(), 3u);
	ASSERT_TRUE(all[0] == Cert(Pem_leaf));
	ASSERT_TRUE(all[2] == Cert(Pem_root));
	auto first = X509::Load(Bytes(bundle));
	ASSERT_TRUE(first.has_value() && *first == Cert(Pem_leaf));
	return 0;
}

int test_issued_by() {
	const Certificate root = Cert(Pem_root), intermediate = Cert(Pem_int), leaf = Cert(Pem_leaf);
	ASSERT_TRUE(root.IsIssuedBy(root));
	ASSERT_TRUE(intermediate.IsIssuedBy(root));
	ASSERT_TRUE(leaf.IsIssuedBy(intermediate));
	ASSERT_TRUE(Cert(Pem_leaf256).IsIssuedBy(intermediate));
	ASSERT_FALSE(leaf.IsIssuedBy(root));
	ASSERT_FALSE(leaf.IsIssuedBy(Cert(Pem_other)));
	ASSERT_FALSE(intermediate.IsIssuedBy(leaf));
	return 0;
}

int test_chain_valid() {
	const Certificate root = Cert(Pem_root), intermediate = Cert(Pem_int), leaf = Cert(Pem_leaf);
	ASSERT_TRUE(leaf.VerifyChain({}, intermediate, Now));
	ASSERT_TRUE(leaf.VerifyChain(std::span(&intermediate, 1), root, Now));
	ASSERT_TRUE(Cert(Pem_leaf256).VerifyChain({}, intermediate, Now));
	ASSERT_TRUE(intermediate.VerifyChain({}, root, Now));
	ASSERT_TRUE(leaf.VerifyChain({}, intermediate));
	const auto bundle = X509::LoadAll(Bytes(Pem_int));
	ASSERT_TRUE(leaf.VerifyChain(bundle, root, Now));
	return 0;
}

int test_chain_wrong_anchor() {
	const Certificate leaf = Cert(Pem_leaf);
	ASSERT_FALSE(leaf.VerifyChain({}, Cert(Pem_root), Now));
	ASSERT_FALSE(leaf.VerifyChain({}, Cert(Pem_other), Now));
	const Certificate other = Cert(Pem_other);
	ASSERT_FALSE(leaf.VerifyChain(std::span(&other, 1), Cert(Pem_root), Now));
	return 0;
}

int test_chain_validity_period() {
	const Certificate window = Cert(Pem_window), intermediate = Cert(Pem_int);
	ASSERT_TRUE(window.VerifyChain({}, intermediate, Now));
	ASSERT_FALSE(window.VerifyChain({}, intermediate, Date(2024, 12, 31)));
	ASSERT_FALSE(window.VerifyChain({}, intermediate, Date(2030, 1, 2)));
	ASSERT_TRUE(window.IsValidAt(Date(2030, 1, 1)));
	ASSERT_FALSE(Cert(Pem_leaf).VerifyChain({}, intermediate, Date(2019, 6, 1)));
	return 0;
}

int test_chain_ca_constraints() {
	const Certificate root = Cert(Pem_root), intermediate = Cert(Pem_int), sub = Cert(Pem_sub);
	// Openssl accepts the sub CA itself; only the leaf below it exceeds pathlen:0.
	ASSERT_TRUE(sub.VerifyChain({}, intermediate, Now));
	ASSERT_TRUE(Cert(Pem_deep).VerifyChain({}, sub, Now));
	ASSERT_FALSE(Cert(Pem_deep).VerifyChain(std::span(&sub, 1), intermediate, Now));
	const Certificate path[] = {sub, intermediate};
	ASSERT_FALSE(Cert(Pem_deep).VerifyChain(path, root, Now));

	ASSERT_TRUE(Cert(Pem_nocsleaf).IsIssuedBy(Cert(Pem_nocs)));
	ASSERT_FALSE(Cert(Pem_nocsleaf).VerifyChain({}, Cert(Pem_nocs), Now));
	ASSERT_TRUE(Cert(Pem_notcaleaf).IsIssuedBy(Cert(Pem_notca)));
	ASSERT_FALSE(Cert(Pem_notcaleaf).VerifyChain({}, Cert(Pem_notca), Now));
	ASSERT_FALSE(Cert(Pem_leaf).VerifyChain({}, Cert(Pem_leaf256), Now));
	return 0;
}

int test_chain_unknown_critical_extension() {
	const Certificate unknown = Cert(Pem_unknown);
	ASSERT_TRUE(unknown.IsIssuedBy(Cert(Pem_int)));
	ASSERT_FALSE(unknown.VerifyChain({}, Cert(Pem_int), Now));
	return 0;
}

int test_tampered_certificate_fails() {
	const Certificate intermediate = Cert(Pem_int), leaf = Cert(Pem_leaf);
	StormByte::Safe::Binary der = leaf.Der();
	const std::string_view cn = "Test Leaf";
	const std::string_view text(reinterpret_cast<const char*>(der.data()), static_cast<std::size_t>(der.size()));
	const std::size_t at = text.rfind(cn);
	ASSERT_TRUE(at != std::string_view::npos);
	der[StormByte::ByteSize{at}] = std::byte{'X'};
	auto tampered = X509::Load(der.span());
	ASSERT_TRUE(tampered.has_value());
	ASSERT_FALSE(tampered->IsIssuedBy(intermediate));
	ASSERT_FALSE(tampered->VerifyChain({}, intermediate, Now));

	der = leaf.Der();
	der[StormByte::ByteSize{static_cast<std::size_t>(der.size()) - 1}] ^= std::byte{0x01};
	auto bad_signature = X509::Load(der.span());
	ASSERT_TRUE(bad_signature.has_value());
	ASSERT_FALSE(bad_signature->VerifyChain({}, intermediate, Now));
	return 0;
}

int test_malformed_input_fails() {
	ASSERT_FALSE(X509::Load({}).has_value());
	ASSERT_FALSE(X509::Load(Bytes("not a certificate")).has_value());
	ASSERT_FALSE(X509::Load(Bytes("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")).has_value());
	const auto der = Cert(Pem_leaf).Der();
	ASSERT_FALSE(X509::Load(der.span().first(der.span().size() - 1)).has_value());
	StormByte::Safe::Binary trailing = der;
	trailing.push_back(std::byte{0});
	ASSERT_FALSE(X509::Load(trailing.span()).has_value());
	std::string truncated_bundle(Pem_leaf);
	truncated_bundle.append("-----BEGIN CERTIFICATE-----\nMIIB\n");
	ASSERT_TRUE(X509::LoadAll(Bytes(truncated_bundle)).empty());
	return 0;
}

int main() {
	int result = 0;
	try {
		result += test_parse_fields();
		result += test_public_key();
		result += test_save_roundtrip();
		result += test_load_all_bundle();
		result += test_issued_by();
		result += test_chain_valid();
		result += test_chain_wrong_anchor();
		result += test_chain_validity_period();
		result += test_chain_ca_constraints();
		result += test_chain_unknown_critical_extension();
		result += test_tampered_certificate_fails();
		result += test_malformed_input_fails();
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

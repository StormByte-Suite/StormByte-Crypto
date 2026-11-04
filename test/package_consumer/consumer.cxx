// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial

#include <StormByte/buffer/fifo.hxx>
#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/logger/log.hxx>
#include <StormByte/system/host.hxx>

#include <climits>
#include <cstddef>
#include <sstream>
#include <string>
#include <string_view>

int main() {
	const StormByte::Crypto::Hasher::SHA256 hasher;
	StormByte::Buffer::FIFO hash;
	if (!hasher.Hash(std::string_view("HashThisString"), hash))
		return 1;

	StormByte::Safe::Binary digest;
	if (!hash.Extract(hash.Available(), digest))
		return 2;
	std::string hex;
	for (const std::byte octet : digest)
		hex.push_back(static_cast<char>(octet));
	if (hex != "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777")
		return 3;

	std::ostringstream output;
	StormByte::Logger::Log log(output);
	log << "crypto consumer" << std::endl;
	if (output.str().find("crypto consumer") == std::string::npos)
		return 4;

	const StormByte::System::Host::CPU cpu;
	return cpu.Bitness() == sizeof(void*) * CHAR_BIT ? 0 : 5;
}

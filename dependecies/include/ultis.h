#pragma once

namespace ulti
{
	inline void Encrypt(char* data, size_t length)
	{
		const char* key = "P7_PROT!";

		// xor encryption 
		for (size_t i = 0; i < length; i++) {
			data[i] ^= key[i % 8];
		}
	}
};
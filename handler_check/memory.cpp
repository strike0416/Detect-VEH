#include "memory.h"

namespace memory
{
	bool is_readable(uintptr_t start, size_t size)
	{
		uint8_t* ptr = reinterpret_cast<uint8_t*>(start);
		auto end = ptr + size;
		while (ptr < end)
		{
			MEMORY_BASIC_INFORMATION mbi{};
			if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
				return false;

			if (!(mbi.State == MEM_COMMIT &&
				(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
				!(mbi.Protect & PAGE_GUARD)))
				return false;

			ptr += mbi.RegionSize;
		}

		return true;
	}

	std::vector<std::pair<uint8_t, bool>> string_to_pattern(const char* pattern)
	{
		auto hex_to_nibble = [](char c) -> uint8_t
			{
				if (c >= '0' && c <= '9') return c - '0';
				if (c >= 'A' && c <= 'F') return c - 'A' + 10;
				if (c >= 'a' && c <= 'f') return c - 'a' + 10;
				return 0;
			};

		std::vector<std::pair<uint8_t, bool>> ptrn;
		size_t length = std::strlen(pattern);
		for (int i = 0; i < length; ++i)
		{
			if (pattern[i] == ' ')
				continue;

			if (pattern[i] == '?')
			{
				ptrn.push_back(std::make_pair(0, true));
				if (i + 1 < length && pattern[i + 1] == '?')
					++i;
			}
			else
			{
				auto front_nibble = hex_to_nibble(pattern[i]);
				if (i + 1 >= length || pattern[i + 1] == ' ')
					ptrn.push_back(std::make_pair(front_nibble, false));
				else
				{
					auto byte = (front_nibble << 4) | hex_to_nibble(pattern[i + 1]);
					ptrn.push_back(std::make_pair(byte, false));
					++i;
				}
			}
		}
		return ptrn;
	}

	uintptr_t pattern_scan(uintptr_t start, size_t size, const char* pattern)
	{
		if (!is_readable(start, size))
			return 0;

		auto ptrn = string_to_pattern(pattern);

		auto buffer = reinterpret_cast<uint8_t*>(start);
		const size_t length = ptrn.size();
		for (uintptr_t i = 0; i < size - length; ++i)
		{
			bool match = true;
			for (size_t j = 0; j < length; ++j)
			{
				if (!ptrn[j].second && ptrn[j].first != buffer[i + j])
				{
					match = false;
					break;
				}
			}

			if (match)
				return reinterpret_cast<uintptr_t>(buffer) + i;
		}

		return 0;
	}
}

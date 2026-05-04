#ifndef MEMORY_H
#define MEMORY_H
#include <Windows.h>
#include <cstdint>
#include <vector>

namespace memory
{
	bool is_readable(uintptr_t start, size_t size);

	//BYTE, wild card
	std::vector<std::pair<uint8_t, bool>> string_to_pattern(const char* pattern);

	//pattern scan for memory region
	uintptr_t pattern_scan(uintptr_t start, size_t size, const char* pattern);
}

#endif

#ifndef ANTI_HANDLER_H
#define ANTI_HANDLER_H
#include "memory.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <expected>

namespace anti_debug
{
	typedef struct _VECTORED_HANDLER_ENTRY
	{
		LIST_ENTRY entry;
		PVOID refs;
		PVOID unknown;
		PVECTORED_EXCEPTION_HANDLER encoded_handler;
	} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY;

	typedef struct _VECTORED_HANDLER_LIST
	{
		PVOID mutex_exception;
		PVECTORED_HANDLER_ENTRY first_exception_handler;
		PVECTORED_HANDLER_ENTRY last_exception_handler;
		PVOID mutex_continue;
		PVECTORED_HANDLER_ENTRY first_continue_handler;
		PVECTORED_HANDLER_ENTRY last_continue_handler;
	} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST;

	ULONG get_process_cookie();
	std::expected<std::uint32_t, std::string> get_cached_process_cookie();

	std::uint64_t decode_pointer(std::uint64_t ptr, std::uint32_t process_cookie);

	std::expected<PVECTORED_HANDLER_LIST, std::string> get_vectored_handler_list();

	std::expected<std::vector<std::uint64_t>, std::string> scan_vectored_exception_handlers();
}

#endif

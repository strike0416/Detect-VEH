#include "anti_handler.h"

namespace anti_debug
{
	typedef enum _PROCESSINFOCLASS
	{
		PROCESS_BASIC_INFORMATION,
		PROCESS_COOKIE = 36
	} PROCESSINFOCLASS;;
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

	ULONG get_process_cookie()
	{
		pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		
		ULONG process_cookie = 0;
		NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), PROCESS_COOKIE, &process_cookie, sizeof(process_cookie), NULL);
		if (status != 0)
			return 0;

		return process_cookie;
	}

	std::expected<uint32_t, std::string> get_cached_process_cookie()
	{
		auto ntdll = GetModuleHandleA("ntdll.dll");
		uintptr_t pRtlDecodePointer = (uintptr_t)GetProcAddress(ntdll, "RtlDecodePointer");
		uintptr_t a1 = memory::pattern_scan(pRtlDecodePointer, 0x20, "0F 84");//find je X
		if (!a1)
			return std::unexpected("failed to find opcode[je] in RtlDecodePointer");

		uintptr_t a2 = a1 + 0x6 + *(uint32_t*)(a1 + 0x2);//jump to ntqueryinformationprocess condition
		uintptr_t a3 = memory::pattern_scan(a2, 0x50, "8B 54 24 48 89 15");//find mov edx,[rsp+48]	mov [cached_cookie],edx
		if (!a3)
			return std::unexpected("failed to find opcode[mov edx,[rsp+48]] in RtlDecodePointer");

		uintptr_t cached_cookie_ptr = a3 + 0x4 + 0x6 + *(uint32_t*)(a3 + 0x6);
		return *(uint32_t*)(cached_cookie_ptr);
	}

	uintptr_t decode_pointer(uintptr_t ptr, uint32_t process_cookie)
	{
		return _rotr64(ptr, 64 - (process_cookie & 0x3F)) ^ process_cookie;
	}

	std::expected<PVECTORED_HANDLER_LIST, std::string> get_vectored_handler_list()
	{
		auto ntdll = GetModuleHandleA("ntdll.dll");
		auto pRtlAddVectoredExceptionHandler = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler"));
		while (pRtlAddVectoredExceptionHandler[0] != 0xE9)
			pRtlAddVectoredExceptionHandler++;
		
		auto offset = *reinterpret_cast<int32_t*>(pRtlAddVectoredExceptionHandler + 1);
		auto RtlpAddVectoredExceptionHandler = reinterpret_cast<uintptr_t>(pRtlAddVectoredExceptionHandler + 5) + offset;
		auto scan_base = memory::pattern_scan(pRtlAddVectoredExceptionHandler, 0x250, "48 8D 0D ? ? ? ? 48");
		if (scan_base == 0)
			return std::unexpected("pattern_scan failed.");

		auto vectored_handler_ptr = scan_base + *(uint32_t*)(scan_base + 0x3) + 0x7;
		return reinterpret_cast<PVECTORED_HANDLER_LIST>(vectored_handler_ptr);
	}

	std::expected<std::vector<uintptr_t>, std::string> scan_vectored_exception_handlers()
	{
		auto process_cookie = get_process_cookie();
		if (!process_cookie)
			return std::unexpected("get_process_cookie().NtQueryInformationProcess failed.");

		auto vh_result = get_vectored_handler_list();
		if (!vh_result)
			return std::unexpected("get_vectored_handler_list()." + vh_result.error());

		std::vector<uintptr_t> vectored_exception_handlers;

		auto vectored_handler_list = *vh_result;
		auto exception_handler = vectored_handler_list->first_exception_handler;
		auto last_exception_handler = vectored_handler_list->last_exception_handler;
		do
		{
			if (reinterpret_cast<uintptr_t>(exception_handler) == reinterpret_cast<uintptr_t>(vectored_handler_list) + 0x8)
				break;

			auto decoded_handler = decode_pointer(reinterpret_cast<uintptr_t>(exception_handler->encoded_handler), process_cookie);
			vectored_exception_handlers.push_back(decoded_handler);
			exception_handler = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(exception_handler->entry.Flink);
		} while (exception_handler != last_exception_handler);

		return vectored_exception_handlers;
	}
}

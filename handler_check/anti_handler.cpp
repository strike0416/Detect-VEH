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

	std::expected<std::uint32_t, std::string> get_cached_process_cookie()
	{
		auto ntdll = GetModuleHandleA("ntdll.dll");
		std::uint64_t pRtlDecodePointer = (std::uint64_t)GetProcAddress(ntdll, "RtlDecodePointer");
		std::uint64_t a1 = memory::pattern_scan(pRtlDecodePointer, 0x20, "0F 84");//find je X
		if (!a1)
			return std::unexpected("failed to find opcode[je] in RtlDecodePointer");

		std::uint64_t a2 = a1 + 0x6 + *(std::uint32_t*)(a1 + 0x2);//jump to ntqueryinformationprocess condition
		std::uint64_t a3 = memory::pattern_scan(a2, 0x50, "8B 54 24 48 89 15");//find mov edx,[rsp+48]	mov [cached_cookie],edx
		if (!a3)
			return std::unexpected("failed to find opcode[mov edx,[rsp+48]] in RtlDecodePointer");

		std::uint64_t cached_cookie_ptr = a3 + 0x4 + 0x6 + *(std::uint32_t*)(a3 + 0x6);
		return *(std::uint32_t*)(cached_cookie_ptr);
	}

	std::uint64_t decode_pointer(std::uint64_t ptr, std::uint32_t process_cookie)
	{
		return _rotr64(ptr, 64 - (process_cookie & 0x3F)) ^ process_cookie;
	}

	std::expected<PVECTORED_HANDLER_LIST, std::string> get_vectored_handler_list()
	{
		auto ntdll = GetModuleHandleA("ntdll.dll");
		std::uint64_t pRtlAddVectoredExceptionHandler = (std::uint64_t)GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler");

		std::uint64_t scan_base = memory::pattern_scan(pRtlAddVectoredExceptionHandler, 0x250, "83 E0 3F 48 8D 3D");
		if (scan_base == 0)
			return std::unexpected("pattern_scan failed.");

		std::uint32_t offset = *(std::uint32_t*)(scan_base + 0x6);//lea rcx, [] < scan
		std::uint64_t vectored_handler_ptr = scan_base + 0x3 + offset + 0x7;
		return reinterpret_cast<PVECTORED_HANDLER_LIST>(vectored_handler_ptr);
	}

	std::expected<std::vector<std::uint64_t>, std::string> scan_vectored_exception_handlers()
	{
		auto process_cookie = get_process_cookie();
		if (!process_cookie)
			return std::unexpected("get_process_cookie().NtQueryInformationProcess failed.");

		auto vh_result = get_vectored_handler_list();
		if (!vh_result)
			return std::unexpected("get_vectored_handler_list()." + vh_result.error());

		std::vector<std::uint64_t> vectored_exception_handlers;

		auto vectored_handler_list = *vh_result;
		auto exception_handler = vectored_handler_list->first_exception_handler;
		auto last_exception_handler = vectored_handler_list->last_exception_handler;
		do
		{
			if (reinterpret_cast<uint64_t>(exception_handler) == reinterpret_cast<uint64_t>(vectored_handler_list) + 0x8)
				break;

			auto decoded_handler = decode_pointer(reinterpret_cast<std::uint64_t>(exception_handler->encoded_handler), process_cookie);
			vectored_exception_handlers.push_back(decoded_handler);
			exception_handler = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(exception_handler->entry.Flink);
		} while (exception_handler != last_exception_handler);

		return vectored_exception_handlers;
	}
}

// Copyright (c) 2024 A.A.A. (contact at aeverless dot dev)
//
// Distributed under the MIT License.
// A copy of the license is present in the LICENSE file.

#if !defined(WORM_POSIX) && !defined(WORM_WINDOWS)

#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
#	define WORM_POSIX
#elif defined(_WIN32)
#	define WORM_WINDOWS
#else
#	error unsupported target operating system
#endif

#endif

#include "worm/worm.hpp"

#include <system_error>

#if defined(WORM_POSIX)

#	define WORM_ERRNO (errno)

#	include <fstream>

#	ifdef __cpp_lib_format
#		include <format>
#	endif

#	include <sys/uio.h>

#elif defined(WORM_WINDOWS)

#	define WORM_ERRNO (static_cast<int>(GetLastError()))

#	define WIN32_LEAN_AND_MEAN

#	include <processthreadsapi.h>
#	include <errhandlingapi.h>
#	include <stringapiset.h>
#	include <libloaderapi.h>
#	include <handleapi.h>
#	include <memoryapi.h>
#	include <minwindef.h>
#	include <winnls.h>
#	include <psapi.h>

#endif

namespace worm
{
namespace
{
[[nodiscard]]
inline auto make_system_error(char const* what_arg) noexcept -> std::system_error
{
	return {
		{WORM_ERRNO, std::system_category()},
		what_arg
	};
}
}

template <handle_mode Mode>
struct handle<Mode>::system_handle
{
	using handle_type = handle<Mode>;

#ifdef WORM_WINDOWS
	void* handle{};

	explicit system_handle(pid_t pid)
		: handle{OpenProcess(
			  (handle_type::readable ? PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION : 0) |
				  (handle_type::writable ? PROCESS_VM_OPERATION | PROCESS_VM_WRITE : 0),
			  false,
			  pid
		  )}
	{
		if (!handle)
		{
			throw make_system_error("failed to open a process handle");
		}
	}

	~system_handle()
	{
		CloseHandle(handle);
	}
#endif
};

template <handle_mode Mode>
handle<Mode>::handle(pid_t pid)
	: pid_{pid}
	, system_handle_{std::make_unique<system_handle>(pid)}
{}

template <handle_mode Mode>
handle<Mode>::~handle() = default;

template <handle_mode Mode>
auto handle<Mode>::pid() const noexcept -> pid_t
{
	return pid_;
}

template <handle_mode Mode>
auto handle<Mode>::read_bytes(address_t src, void* dst, std::size_t size) const -> std::size_t
	requires readable
{
#ifdef WORM_POSIX
	iovec local{dst, size};
	iovec remote{reinterpret_cast<void*>(src), size};
#endif

	if (
#if defined(WORM_POSIX)
		ssize_t const bytes_read = process_vm_readv(pid_, &local, 1, &remote, 1, 0); bytes_read >= 0
#elif defined(WORM_WINDOWS)
		std::size_t bytes_read = 0; ReadProcessMemory(system_handle_->handle, reinterpret_cast<void const*>(src), dst, size, &bytes_read)
#endif
	)
	{
		return bytes_read;
	}

	throw make_system_error("failed to read from virtual memory");
}

template <handle_mode Mode>
auto handle<Mode>::write_bytes(address_t dst, void const* src, std::size_t size) const -> std::size_t
	requires writable
{
#ifdef WORM_POSIX
	iovec local{reinterpret_cast<void*>(src), size};
	iovec remote{dst, size};
#endif

	if (
#if defined(WORM_POSIX)
		ssize_t const bytes_written = process_vm_writev(pid_, &local, 1, &remote, 1, 0); bytes_written >= 0
#elif defined(WORM_WINDOWS)
		std::size_t bytes_written = 0; WriteProcessMemory(system_handle_->handle, reinterpret_cast<void*>(dst), src, size, &bytes_written)
#endif
	)
	{
		return bytes_written;
	}

	throw make_system_error("failed to write to virtual memory");
}

template <handle_mode Mode>
auto handle<Mode>::regions() const -> std::vector<memory_region>
	requires readable
{
	std::vector<memory_region> regions;

#if defined(WORM_POSIX)
	std::ifstream f(
#	ifdef __cpp_lib_format
		std::format("/proc/{}/maps", pid_)
#	else
		"/proc/" + std::to_string(pid_) + "/maps"
#	endif
	);

	static constexpr char column_delim = ' ';
	static constexpr char range_delim  = '-';

	while (!f.eof())
	{
		std::string row;
		std::getline(f, row);

		std::size_t const first_delim_index = row.find(column_delim);
		if (first_delim_index == std::string::npos)
		{
			break;
		}

		std::string_view const range_str(row.substr(0, first_delim_index));
		std::size_t const      range_delim_index = range_str.find(range_delim);

		regions.push_back({
			row.substr(row.rfind(column_delim) + 1),
			{std::stoull(range_str.substr(0, range_delim_index), nullptr, 16), std::stoull(range_str.substr(range_delim_index + 1), nullptr, 16)}
		});
	}
#elif defined(WORM_WINDOWS)
	DWORD size;

	void* const& windows_handle = system_handle_->handle;

	if (!EnumProcessModules(windows_handle, nullptr, 0, &size))
	{
		throw make_system_error("failed to count process modules during initial enumeration");
	}

	std::size_t const module_count = size / sizeof(HMODULE);
	auto const        modules      = std::make_unique<HMODULE[]>(module_count);

	if (!EnumProcessModules(windows_handle, modules.get(), size, &size))
	{
		throw make_system_error("failed to enumerate process modules");
	}

	static constexpr std::size_t max_path_size = 32'768;
	wchar_t                      raw_module_name[max_path_size];

	for (std::size_t i = 0; i < module_count; ++i)
	{
		auto* const& module_handle = modules[i];

		int const name_size = static_cast<int>(GetModuleFileNameW(module_handle, raw_module_name, max_path_size));

		int const bytes_required = WideCharToMultiByte(CP_UTF8, 0, raw_module_name, name_size, nullptr, 0, nullptr, nullptr);

		std::string module_name(bytes_required, 0);

		WideCharToMultiByte(CP_UTF8, 0, raw_module_name, name_size, module_name.data(), bytes_required, nullptr, nullptr);

		MODULEINFO module_info;
		GetModuleInformation(windows_handle, module_handle, &module_info, sizeof(module_info));

		auto const base_addr = reinterpret_cast<address_t>(module_handle);
		regions.push_back({
			module_name,
			{base_addr, base_addr + module_info.SizeOfImage}
		});
	}
#endif

	return regions;
}

template struct handle<handle_mode::in>;
template struct handle<handle_mode::out>;
template struct handle<handle_mode::in | handle_mode::out>;
}

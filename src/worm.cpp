// Copyright (c) 2024 A.A.A. (contact at aeverless dot dev)
//
// Distributed under the MIT License.
// A copy of the license is present in the LICENSE file.

#include "worm.hpp"

#if defined(WORM_POSIX)

#  define WORM_ERRNO (errno)

#  include <fstream>

#  ifdef __cpp_lib_format
#    include <format>
#  endif

#  include <sys/uio.h>

#elif defined(WORM_WINDOWS)

#  define WORM_ERRNO static_cast<int>(GetLastError())

#  include <memory>

#  define WIN32_LEAN_AND_MEAN

#  include <errhandlingapi.h>
#  include <handleapi.h>
#  include <libloaderapi.h>
#  include <memoryapi.h>
#  include <minwindef.h>
#  include <processthreadsapi.h>
#  include <psapi.h>

#endif


namespace worm
{
[[nodiscard]] static inline std::system_error make_system_error(char const* what_arg) noexcept
{
	return std::system_error({WORM_ERRNO, std::system_category()}, what_arg);
}

basic_handle::basic_handle(pid_t pid, [[maybe_unused]] unsigned long system_access_flags)
	: pid_(pid)
#ifdef WORM_WINDOWS
	, windows_handle_(OpenProcess(system_access_flags, false, pid))
#endif
{
#ifdef WORM_WINDOWS
	if (!windows_handle_)
	{
		throw make_system_error("failed to open a process handle");
	}
#endif
}

basic_handle::basic_handle(pid_t pid, [[maybe_unused]] handle_mode mode)
	: basic_handle(
		pid,
#if defined(WORM_POSIX)
		0
#elif defined(WORM_WINDOWS)
		((mode & handle_mode::in)  ? PROCESS_VM_READ      | PROCESS_QUERY_LIMITED_INFORMATION : 0) |
		((mode & handle_mode::out) ? PROCESS_VM_OPERATION | PROCESS_VM_WRITE                  : 0)
#endif
	  )
{}

basic_handle::~basic_handle() noexcept
{
#ifdef WORM_WINDOWS
	CloseHandle(windows_handle_);
#endif
}

pid_t basic_handle::pid() const noexcept
{
	return pid_;
}

std::size_t basic_handle::read_bytes_impl(void const* src, void* dst, std::size_t size) const
{
#ifdef WORM_POSIX
	iovec local{dst, size};
	iovec remote{const_cast<void*>(src), size};
#endif

	if (
#if defined(WORM_POSIX)
		ssize_t const bytes_read = process_vm_readv(pid_, &local, 1, &remote, 1, 0); bytes_read >= 0
#elif defined(WORM_WINDOWS)
		std::size_t bytes_read = 0; ReadProcessMemory(windows_handle_, src, dst, size, &bytes_read)
#endif
	)
	{
		return bytes_read;
	}

	throw make_system_error("failed to read from virtual memory");
}

std::size_t basic_handle::write_bytes_impl(void* dst, void const* src, std::size_t size) const
{
#ifdef WORM_POSIX
	iovec local{const_cast<void*>(src), size};
	iovec remote{dst, size};
#endif

	if (
#if defined(WORM_POSIX)
		ssize_t const bytes_written = process_vm_writev(pid_, &local, 1, &remote, 1, 0); bytes_written >= 0
#elif defined(WORM_WINDOWS)
		std::size_t bytes_written = 0; WriteProcessMemory(windows_handle_, dst, src, size, &bytes_written)
#endif
	)
	{
		return bytes_written;
	}

	throw make_system_error("failed to write to virtual memory");
}

std::vector<memory_region> basic_handle::regions_impl() const
{
	std::vector<memory_region> regions;

#if defined(WORM_POSIX)
	std::wifstream f(
#  ifdef __cpp_lib_format
		std::format("/proc/{}/maps", pid_)
#  else
		"/proc/" + std::to_string(pid_) + "/maps"
#  endif
	);

	static constexpr wchar_t column_delim = L' ';
	static constexpr wchar_t range_delim = L'-';

	while (!f.eof())
	{
		std::wstring row;
		std::getline(f, row);

		std::size_t const first_delim_index = row.find(column_delim);
		if (first_delim_index == std::wstring::npos)
		{
			break;
		}

		std::wstring_view const range_str(row.substr(0, first_delim_index));
		std::size_t const range_delim_index = range_str.find(range_delim);

		regions.push_back({
			row.substr(row.rfind(column_delim) + 1),
			{
				std::stoull(range_str.substr(0, range_delim_index), nullptr, 16),
				std::stoull(range_str.substr(range_delim_index + 1), nullptr, 16)
			}
		});
	}
#elif defined(WORM_WINDOWS)
	DWORD size;
	if (!EnumProcessModules(windows_handle_, nullptr, 0, &size))
	{
		throw make_system_error("failed to count process modules during initial enumeration");
	}

	std::size_t const module_count = size / sizeof(HMODULE);
	auto const modules = std::make_unique<HMODULE[]>(module_count);

	if (!EnumProcessModules(windows_handle_, modules.get(), size, &size))
	{
		throw make_system_error("failed to enumerate process modules");
	}

	static constexpr std::size_t max_path_size = 32'768;
	wchar_t module_name[max_path_size];

	for (std::size_t i = 0; i < module_count; ++i)
	{
		auto const& module_handle = modules[i];

		GetModuleFileNameW(module_handle, module_name, max_path_size);

		MODULEINFO module_info;
		GetModuleInformation(windows_handle_, module_handle, &module_info, sizeof(module_info));

		auto const base_addr = reinterpret_cast<address_t>(module_handle);
		regions.push_back({module_name, {base_addr, base_addr + module_info.SizeOfImage}});
	}
#endif

	return regions;
}
}

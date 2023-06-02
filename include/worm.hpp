// Copyright (c) 2023 A.A.A. (contact at aeverless dot dev)
//
// Distributed under the MIT License.
// A copy of the license is present in the LICENSE file.

#ifndef WORM_HPP
#define WORM_HPP

#include <ranges>
#include <vector>
#include <string>
#include <cstdint>
#include <type_traits>

#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
#  define WORM_POSIX
#elif defined(_WIN32)
#  define WORM_WINDOWS
#else
#  error unsupported target operating system
#endif


/// worm library namespace.
namespace worm
{
/// Memory region.
struct memory_region
{
	/// Name string.
	std::wstring name;

	/// Address space range.
	std::ranges::iota_view<std::uintptr_t, std::uintptr_t> range;
};

/**
 * @brief Basic handle with no public functionality that binds to an external process.
 *
 * @note It is not meant to be directly used. Use `worm::handle` instead.
 */
class basic_handle
{
protected:
	/// Process ID
	std::size_t pid_;

#ifdef WORM_WINDOWS
	/// Windows handle pointer. Only defined on Windows.
	void* windows_handle_;
#endif

	/**
	 * @brief Private implementation of reading bytes.
	 * It is not meant to be directly called.
	 *
	 * @param[in]  src  remote buffer
	 * @param[out] dst  local buffer
	 * @param[in]  size number of bytes to read
	 *
	 * @throws std::system_error on failed read attempt
	 *
	 * @note This member function should be conditionally exposed on compile-time
	 *       in order to avoid runtime errors because of insufficient privileges.
	 */
	std::size_t read_bytes_impl(void const* src, void* dst, std::size_t size) const;

	/**
	 * @brief Private implementation of writing bytes.
	 * It is not meant to be directly called.
	 *
	 * @param[out] dst  remote buffer
	 * @param[in]  src  local buffer
	 * @param[in]  size number of bytes to write
	 *
	 * @throws std::system_error on failed write attempt
	 *
	 * @note This member function should be conditionally exposed on compile-time
	 *       in order to avoid runtime errors because of insufficient privileges.
	 */
	std::size_t write_bytes_impl(void* dst, void const* src, std::size_t size) const;

	/**
	 * @brief Private implementation of enumerating virtual memory regions.
	 * It is not meant to be directly called.
	 *
	 * @throws std::system_error if failed to enumerate memory regions
	 *
	 * @note This member function should be conditionally exposed on compile-time
	 *       in order to avoid runtime errors because of insufficient privileges.
	 */
	[[nodiscard]] std::vector<memory_region> regions_impl() const;

public:
	/**
	 * @brief Process open mode.
	 *
	 * It is unused on POSIX-compliant systems.
	 */
	enum open_mode
	{
		/**
		 * @brief Read (input) flag.
		 *
		 * @note On Windows, during handle construction, this enables
		 *       `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`.
		 */
		in = 1 << 0,

		/**
		 * @brief Read (input) flag.
		 *
		 * @note On Windows, during handle construction, this enables
		 *       `PROCESS_VM_OPERATION | PROCESS_VM_WRITE`.
		 */
		out = 1 << 1,
	};

	/// Default handle constructor.
	explicit basic_handle() noexcept = default;

	/**
	 * @brief Construct and bind a handle with manual system access flags.
	 *
	 * Bind a handle to a process with given pid and system process access flags.
	 *
	 * @param pid                 process id
	 * @param system_access_flags access flags that will be passed to the system call (if one)
	 *
	 * @throws std::system_error if failed to bind a handle
	 *
	 * @note Only call this constructor overload if you know what specific flags you need.
	 *       Constructing a handle with this constructor may make it impossible to catch
	 *       privilege errors on compile-time, or may make privilege escalation via
	 *       conversion or other means possible.
	 */
	explicit basic_handle(std::size_t pid, unsigned long system_access_flags);

	/**
	 * @brief Construct and bind a handle.
	 *
	 * Bind a handle to a process with given pid and open mode.
	 * Uses default mappings of open mode to system access flags.
	 *
	 * @param pid  process id
	 * @param mode process open mode
	 *
	 * @throws std::system_error if failed to bind a handle
	 */
	explicit basic_handle(std::size_t pid, open_mode mode = {});

	/// Handle destructor.
	~basic_handle() noexcept;
};

/**
 * @brief Combine two open modes via disjunction.
 *
 * @param lhs left-hand side parameter
 * @param rhs right-hand side parameter
 *
 * @relatesalso worm::basic_handle::open_mode
 */
[[nodiscard]] constexpr auto operator|(basic_handle::open_mode lhs, basic_handle::open_mode rhs) noexcept
{
	return static_cast<basic_handle::open_mode>(static_cast<int>(lhs) | static_cast<int>(rhs));
}

/**
 * @brief Handle that binds to an external process.
 *
 * It is used to interact with external process' virtual memory.
 *
 * @tparam mode handle access mode
 *
 * @note Usefulness of passing open mode via template parameters comes from
 *       the ability to catch certain privilege errors, such as trying to read
 *       on a write-only handle, on compile-time instead of throwing exceptions
 *       on runtime.
 */
template <basic_handle::open_mode mode>
class handle : public basic_handle
{
	using basic_handle::basic_handle;

public:
	/**
	 * @brief Construct a handle.
	 *
	 * Bind a handle to a process with given pid.
	 *
	 * @param pid process id
	 *
	 * @throws std::system_error on failure to bind a handle
	 *
	 * @note This constructor uses default mappings of `worm::basic_handle::open_mode`
	 *       to system access flags. If you want to pass other access flags,
	 *       see the overload with `unsigned long` as the second parameter.
	 */
	explicit handle(std::size_t pid)
		: basic_handle(pid, mode)
	{}

	/// Underlying value is true if read member functions are available, false otherwise.
	using is_readable = std::bool_constant<mode & open_mode::in>;

	/// Underlying value is true if write member functions are available, false otherwise.
	using is_writable = std::bool_constant<mode & open_mode::out>;

	/**
	 * @brief Enumerate virtual memory regions.
	 *
	 * @throws std::system_error if could not enumerate memory regions
	 */
	[[nodiscard]] auto regions() const
		requires is_readable::value
	{
		return regions_impl();
	}

	/**
	 * @brief Read bytes from virtual memory into a buffer.
	 *
	 * @param[in]  addr remote virtual memory address
	 * @param[out] dst  local buffer
	 * @param[in]  size number of bytes to read
	 *
	 * @throws std::system_error on failed read attempt
	 */
	auto read_bytes(std::uintptr_t addr, void* dst, std::size_t size) const
		requires is_readable::value
	{
		return read_bytes_impl(reinterpret_cast<void const*>(addr), dst, size);
	}

	/**
	 * @brief Read value from virtual memory.
	 *
	 * @tparam ValueType type of value to read
	 *
	 * @param[in] addr remote virtual memory address
	 *
	 * @throws std::system_error on failed read attempt
	 */
	template <typename ValueType>
	[[nodiscard]] auto read(std::uintptr_t addr) const
		requires is_readable::value
	{
		ValueType value;
		read_bytes(addr, &value, sizeof(value));
		return value;
	}

	/**
	 * @brief Write bytes from a buffer to virtual memory.
	 *
	 * @param[in] addr remote virtual memory address
	 * @param[in] src  local buffer
	 * @param[in] size number of bytes to write
	 *
	 * @throws std::system_error on failed write attempt
	 */
	auto write_bytes(std::uintptr_t addr, void const* src, std::size_t size) const
		requires is_writable::value
	{
		return write_bytes_impl(reinterpret_cast<void*>(addr), src, size);
	}

	/**
	 * @brief Write value to virtual memory.
	 *
	 * @tparam ValueType type of value to write
	 *
	 * @param[in] addr  remote virtual memory address
	 * @param[in] value value to write
	 *
	 * @throws std::system_error on failed write attempt
	 */
	template <typename ValueType>
	auto write(std::uintptr_t addr, ValueType const& value) const
		requires is_writable::value
	{
		return write_bytes(addr, &value, sizeof(value));
	}

	/**
	 * @brief Bound value.
	 * It simplifies repeatedly reading or writing to value at the same virtual address.
	 *
	 * @tparam ValueType type of value to hold
	 */
	template <typename ValueType>
	class bound
	{
	protected:
		handle<mode> const& h_;
		std::uintptr_t const addr_;

	public:
		using handle_type = std::remove_cvref_t<decltype(h_)>;
		using value_type = ValueType;

		/**
		 * @brief Construct bound value.
		 *
		 * @param h    handle
		 * @param addr remote virtual memory address
		 */
		explicit bound(handle_type const& h, std::uintptr_t addr) noexcept
			: h_(h)
			, addr_(addr)
		{}

		/**
		 * @brief Read value at bound virtual address.
		 *
		 * @throws std::system_error on failed read attempt
		 */
		[[nodiscard]] auto read() const
			requires handle_type::is_readable::value
		{
			return h_.template read<value_type>(addr_);
		}

		/**
		 * @brief Write to value at bound virtual address.
		 *
		 * @param value value to write
		 *
		 * @throws std::system_error on failed write attempt
		 */
		auto write(value_type const& value) const
			requires handle_type::is_writable::value
		{
			return h_.write(addr_, value);
		}
	};

	/**
	 * @brief Bind value to a virtual address.
	 *
	 * @tparam ValueType type of bound value
	 *
	 * @param addr remote virtual memory address that holds bound value
	 */
	template <typename ValueType>
	[[nodiscard]] auto bind(std::uintptr_t addr) const noexcept
	{
		return bound<ValueType>(*this, addr);
	}
};

/// Handle with read access only.
using ihandle = handle<basic_handle::open_mode::in>;

/// Handle with write access only.
using ohandle = handle<basic_handle::open_mode::out>;

/// Handle with read and write access.
using iohandle = handle<basic_handle::open_mode::in | basic_handle::open_mode::out>;
}

#endif

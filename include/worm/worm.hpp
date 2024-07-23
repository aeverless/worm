#ifndef WORM_HPP
#define WORM_HPP

#include <cstdint>
#include <memory>
#include <ranges>
#include <string>
#include <vector>

namespace worm
{
/// Address type.
using address_t = std::uintptr_t;

/// Process ID type.
using pid_t = std::size_t;

/// Memory region.
struct memory_region
{
	/// Region name.
	std::string name;

	/// Address space range.
	std::ranges::iota_view<address_t, address_t> range;
};

/// Handle mode.
enum struct handle_mode
{
	/**
	 * @brief Read (input) flag.
	 *
	 * @note On Windows, during handle construction, this enables
	 *       `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`.
	 */
	in = 1 << 0,

	/**
	 * @brief Write (output) flag.
	 *
	 * @note On Windows, during handle construction, this enables
	 *       `PROCESS_VM_OPERATION | PROCESS_VM_WRITE`.
	 */
	out = 1 << 1,
};

/**
 * @brief Conjunction of two handle modes.
 *
 * @param[in] lhs left-hand side parameter
 * @param[in] rhs right-hand side parameter
 *
 * @relatesalso worm::handle_mode
 */
[[nodiscard]]
constexpr auto operator&(handle_mode lhs, handle_mode rhs) noexcept -> handle_mode;

/**
 * @brief Disjunction of two handle modes.
 *
 * @param[in] lhs left-hand side parameter
 * @param[in] rhs right-hand side parameter
 *
 * @relatesalso worm::handle_mode
 */
[[nodiscard]]
constexpr auto operator|(handle_mode lhs, handle_mode rhs) noexcept -> handle_mode;

/**
 * @brief Handle that binds to an external process.
 *
 * It is used to interact with external process' virtual memory.
 *
 * @tparam Mode handle access mode
 *
 * @note Usefulness of passing handle mode via template parameters comes from
 *       the ability to catch certain privilege errors, such as trying to read
 *       on a write-only handle, on compile-time instead of throwing exceptions
 *       on runtime.
 */
template <handle_mode Mode>
struct handle
{
	/// Whether or not this handle can be used to read memory.
	static constexpr bool readable = static_cast<bool>(Mode & handle_mode::in);

	/// Whether or not this handle can be used to write memory.
	static constexpr bool writable = static_cast<bool>(Mode & handle_mode::out);

	/**
	 * @brief Bound value.
	 *
	 * It simplifies repeatedly reading or writing to value at a constant virtual address.
	 *
	 * @tparam T type of value to hold
	 */
	template <typename T>
	struct bound;

	/**
	 * @brief Construct a handle.
	 *
	 * Bind a handle to a process with given pid.
	 *
	 * @param[in] pid process id
	 *
	 * @throws `std::system_error` on failure to bind a handle
	 */
	explicit handle(pid_t pid);

	/**
	 * @brief Destruct a handle.
	 *
	 * Close system handle to the bound process.
	 */
	~handle();

	/**
	 * @brief Get PID of the proccess that this handle is attached to.
	 */
	[[nodiscard]]
	auto pid() const noexcept -> pid_t;

	/**
	 * @brief Enumerate virtual memory regions.
	 *
	 * @throws `std::system_error` if could not enumerate memory regions
	 */
	[[nodiscard]]
	auto regions() const -> std::vector<memory_region>
		requires readable;

	/**
	 * @brief Read bytes from virtual memory into a buffer.
	 *
	 * @param[in]  addr remote virtual memory address
	 * @param[out] dst  local buffer
	 * @param[in]  size number of bytes to read
	 *
	 * @throws `std::system_error` on failed read attempt
	 */
	auto read_bytes(address_t src, void* dst, std::size_t size) const -> std::size_t
		requires readable;

	/**
	 * @brief Write bytes from a buffer to virtual memory.
	 *
	 * @param[in] addr remote virtual memory address
	 * @param[in] src  local buffer
	 * @param[in] size number of bytes to write
	 *
	 * @throws `std::system_error` on failed write attempt
	 */
	auto write_bytes(address_t dst, void const* src, std::size_t size) const -> std::size_t
		requires writable;

	/**
	 * @brief Read value from virtual memory.
	 *
	 * @tparam T type of value to read
	 *
	 * @param[in] addr remote virtual memory address
	 *
	 * @throws `std::system_error` on failed read attempt
	 */
	template <typename T>
	[[nodiscard]]
	auto read(address_t addr) const -> T
		requires readable;

	/**
	 * @brief Write value to virtual memory.
	 *
	 * @tparam T type of value to write
	 *
	 * @param[in] addr  remote virtual memory address
	 * @param[in] value value to write
	 *
	 * @throws `std::system_error` on failed write attempt
	 */
	template <typename T>
	auto write(address_t addr, T const& value) const -> std::size_t
		requires writable;

	/**
	 * @brief Bind value to a virtual address.
	 *
	 * @tparam T type of bound value
	 *
	 * @param[in] addr remote virtual memory address that holds bound value
	 */
	template <typename T>
	[[nodiscard]]
	auto bind(address_t addr) const& noexcept -> bound<T>;

private:
	/**
	 * @brief Internal representation of a system handle.
	 *
	 * It is used to access OS-specific API to communicate with other processes.
	 */
	struct system_handle;

	pid_t                          pid_;
	std::unique_ptr<system_handle> system_handle_;
};

template <handle_mode Mode>
template <typename T>
struct handle<Mode>::bound
{
	using handle_type = handle<Mode>;
	using value_type  = T;

	/// Whether or not this bound can be read.
	static constexpr bool readable = handle_type::readable;

	/// Whether or not this bound can be written.
	static constexpr bool writable = handle_type::writable;

	/**
	 * @brief Construct bound value.
	 *
	 * @param[in] h    handle
	 * @param[in] addr remote virtual memory address
	 */
	explicit bound(handle_type const& h, address_t addr) noexcept;

	/**
	 * @brief Read value at bound virtual address.
	 *
	 * @throws `std::system_error` on failed read attempt
	 */
	[[nodiscard]]
	auto read() const -> value_type
		requires readable;

	/**
	 * @brief Write to value at bound virtual address.
	 *
	 * @param[in] value value to write
	 *
	 * @throws `std::system_error` on failed write attempt
	 */
	auto write(value_type const& value) const -> std::size_t
		requires writable;

private:
	handle_type const& h_;
	address_t const    addr_;
};
}

#include "worm.inl"

namespace worm
{
/// Handle with read access only.
using ihandle = handle<handle_mode::in>;

/// Handle with write access only.
using ohandle = handle<handle_mode::out>;

/// Handle with read and write access.
using iohandle = handle<handle_mode::in | handle_mode::out>;
}

#endif

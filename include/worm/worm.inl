// Copyright (c) 2024 A.A.A. (contact at aeverless dot dev)
//
// Distributed under the MIT License.
// A copy of the license is present in the LICENSE file.

namespace worm
{
constexpr auto operator&(handle_mode lhs, handle_mode rhs) noexcept -> handle_mode
{
	return static_cast<handle_mode>(static_cast<int>(lhs) & static_cast<int>(rhs));
}

constexpr auto operator|(handle_mode lhs, handle_mode rhs) noexcept -> handle_mode
{
	return static_cast<handle_mode>(static_cast<int>(lhs) | static_cast<int>(rhs));
}

template <handle_mode Mode>
template <typename T>
auto handle<Mode>::read(address_t addr) const -> T
	requires readable
{
	T value;
	read_bytes(addr, &value, sizeof(value));
	return value;
}

template <handle_mode Mode>
template <typename T>
auto handle<Mode>::write(address_t addr, T const& value) const -> std::size_t
	requires writable
{
	return write_bytes(addr, &value, sizeof(value));
}

template <handle_mode Mode>
template <typename T>
auto handle<Mode>::bind(address_t addr) const& noexcept -> bound<T>
{
	return bound<T>(*this, addr);
}

template <handle_mode Mode>
template <typename T>
handle<Mode>::bound<T>::bound(handle_type const& h, address_t addr) noexcept
	: h_{h}
	, addr_{std::move(addr)}
{}

template <handle_mode Mode>
template <typename T>
auto handle<Mode>::bound<T>::read() const -> value_type
	requires readable
{
	return h_.template read<value_type>(addr_);
}

template <handle_mode Mode>
template <typename T>
auto handle<Mode>::bound<T>::write(value_type const& value) const -> std::size_t
	requires writable
{
	return h_.write(addr_, value);
}
}

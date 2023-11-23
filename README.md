# worm

**worm** is a cross-platform C++20 library that provides several bindings to Windows and POSIX API
with intent to simplify interactions with external processes' virtual memory.

It is highly encouraged that you use this library in conjunction with C++20 STL features.

The library is bare-bones and not meant to be extensively used in projects dealing with memory at a low level.

## Features

- Simple interface for reading from and writing to external processes' virtual memory
- Compile-time safety - privilege errors are caught compile-time
- Portability - the same feature set is available both for Windows and POSIX-compliant system
- Compliance with STL - the library is built with C++20 features in mind

## Exceptions

While using the library, keep in mind that almost all functions in it are potentially throwing (even some constructors).

In most of the examples below, however, there are no `try`-`catch` blocks in order to reduce visual noise.

## Examples

Let `pid` be the process id of an arbitrary running process.

Prerequisite for each of the examples:

```cpp
#include <worm.hpp>
```

### Creating a handle

Constructing a handle will call `OpenProcess` on Windows, or call nothing on POSIX-compliant systems.

#### For reading only

```cpp
worm::ihandle handle(pid);
```

#### For writing only

```cpp
worm::ohandle handle(pid);
```

#### For reading and writing

```cpp
worm::iohandle handle(pid);
```

### Obtaining memory regions

Let `handle` be an instance of `worm::ihandle`, or `worm::ohandle`, or `worm::iohandle`.

```cpp
static_assert(decltype(handle)::is_readable_v);

std::vector<worm::memory_region> regions = handle.regions();
```

### Interacting with virtual memory

Let `addr` be the address of an arbitrary virtual memory location of the aforementioned process.

#### Readable handle

```cpp
static_assert(decltype(handle)::is_readable_v);

auto const value = handle.read<int>(addr);

unsigned char buf[13];
constexpr std::size_t size = 7;

std::size_t const bytes_read = handle.read_bytes(addr, buf, size);
```

#### Writable handle

```cpp
static_assert(decltype(handle)::is_writable_v);

std::size_t const bytes_written_a = handle.write<unsigned long>(addr, 0xdeadbeef);

unsigned char buf[7]{};
constexpr std::size_t size = 4;

std::size_t const bytes_written_b = handle.write_bytes(addr, buf, size);
```

### Bound values

A bound value can be one of the following types:

- `worm::ihandle::bound` - a readable bound
- `worm::ohandle::bound` - a writable bound
- `worm::iohandle::bound` - a readable and writable bound

#### Readable bound value

```cpp
static_assert(decltype(handle)::is_readable_v);

auto const ibound = handle.bind<int>(addr);

int const value = ibound.read();
```

#### Writable bound value

```cpp
static_assert(decltype(handle)::is_writable_v);

auto const obound = handle.bind<int>(addr);

std::size_t const bytes_written = obound.write(1234);
```

### Scanning virtual memory

Say we want to find first four addresses that hold `(int) 213456` in the first memory region.

```cpp
static_assert(decltype(handle)::is_readable_v);

constexpr int sought_value = 213456;

auto const available_range = handle.regions().front().range;

// worm::memory_region::range is a contiguous range of addresses
// belonging to the given range, so you have to be careful with
// the bounds in order to read only what you really need. Here,
// we substract the size of readed value in order to not go out
// of bounds of the address space.
decltype(available_range) range{available_range.front(), available_range.back() - sizeof(sought_value)};

// Be careful to capture handles by reference, or else
// they will be recreated, and that might be not what you want.
auto const pred = [&](worm::address_t const& address)
{
    try
    {
        return handle.read<std::remove_cv_t<decltype(sought_value)>>(address) == sought_value;
    }
    catch (std::system_error const&) {} // Suppress errors

    return false;
};

for (auto const& address : range | std::views::filter(pred) | std::views::take(4))
{
    std::cout << std::hex << address << '\n';
}
```

If we want to scan the entire available memory, we would define `available_range` as follows:

```cpp
auto const regions = handle.regions();

decltype(worm::memory_region::range) available_range{regions.front().range.front(), regions.back().range.back()};
```

## Requirements

The following requirements must be met to be able to build the library:

- C++20 support
- CMake 3.26 or newer

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution guidelines.

## License

The library is licensed under the MIT License.
A copy of the license is available in the [LICENSE](LICENSE) file.

## Authors

A.A.A. (contact at aeverless dot dev)

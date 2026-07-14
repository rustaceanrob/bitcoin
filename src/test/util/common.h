// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_COMMON_H
#define BITCOIN_TEST_UTIL_COMMON_H

#include <crypto/hex_base.h>
#include <key.h>
#include <netaddress.h>
#include <protocol.h>
#include <pubkey.h>
#include <streams.h>

#include <chrono>
#include <optional>
#include <ostream>
#include <ranges>
#include <string>
#include <variant>

/**
 * BOOST_CHECK_EXCEPTION predicates to check the specific validation error.
 * Use as
 * BOOST_CHECK_EXCEPTION(code that throws, exception type, HasReason("foo"));
 */
class HasReason
{
public:
    explicit HasReason(std::string_view reason) : m_reason(reason) {}
    bool operator()(std::string_view s) const { return s.find(m_reason) != std::string_view::npos; }
    bool operator()(const std::exception& e) const { return (*this)(e.what()); }

private:
    const std::string m_reason;
};

// Make types usable in BOOST_CHECK_* @{
namespace std {
template <typename Clock, typename Duration>
inline std::ostream& operator<<(std::ostream& os, const std::chrono::time_point<Clock, Duration>& tp)
{
    return os << tp.time_since_epoch().count();
}

template <typename T> requires std::is_enum_v<T>
inline std::ostream& operator<<(std::ostream& os, const T& e)
{
    return os << static_cast<std::underlying_type_t<T>>(e);
}

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const std::optional<T>& v)
{
    return v ? os << *v
             : os << "std::nullopt";
}
} // namespace std

template <typename T>
concept has_to_string = requires(const T& t) { t.ToString(); };

template <has_to_string T>
inline std::ostream& operator<<(std::ostream& os, const T& obj)
{
    return os << obj.ToString();
}

template <typename T>
concept has_hex_str = requires(const T& v) { { HexStr(v) } -> std::same_as<std::string>; };

template <typename T>
concept has_serialize = requires(const T& v, DataStream& s) { v.Serialize(s); };

template <typename T>
concept pointer =
    std::is_pointer_v<T> &&
    !std::same_as<std::decay_t<T>, char*> &&
    !std::same_as<std::decay_t<T>, const char*>;

template <typename T>
concept pair_like = requires(const T& v) {
    v.first;
    v.second;
};

template <typename T>
concept non_string_range = std::ranges::range<T> && !std::is_convertible_v<T, std::string_view>;

template <typename T>
concept is_variant = requires { std::variant_size<T>::value; };


inline std::ostream& operator<<(std::ostream& os, const CService& s)
{
    return os << s.ToStringAddrPort();
}

inline std::ostream& operator<<(std::ostream& os, const CAddress& a)
{
    return os << a.ToStringAddrPort();
}

inline std::ostream& operator<<(std::ostream& os, const CExtKey& k)
{
    unsigned char code[BIP32_EXTKEY_SIZE];
    k.Encode(code);
    return os << HexStr(code);
}

inline std::ostream& operator<<(std::ostream& os, const CExtPubKey& k)
{
    unsigned char code[BIP32_EXTKEY_SIZE];
    k.Encode(code);
    return os << HexStr(code);
}

// @}

#endif // BITCOIN_TEST_UTIL_COMMON_H

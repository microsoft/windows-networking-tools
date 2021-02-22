#pragma once

#include <string>
#include <vector>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <wil/resource.h>

namespace multipath {

class Sockaddr
{
public:
    static constexpr size_t IpStringMaxLength = 65;

    enum class ByteOrder
    {
        HostOrder,
        NetworkOrder,
    };

    enum class AddressType
    {
        Loopback,
        Any,
    };

    static std::vector<Sockaddr> ResolveName(PCWSTR);

    Sockaddr() noexcept = default;
    explicit Sockaddr(short family, AddressType type = AddressType::Any) noexcept;
    explicit Sockaddr(_In_reads_bytes_(inLength) const SOCKADDR* inAddr, size_t inLength) noexcept;
    explicit Sockaddr(const SOCKADDR_IN*) noexcept;
    explicit Sockaddr(const SOCKADDR_IN6*) noexcept;
    explicit Sockaddr(const SOCKADDR_INET*) noexcept;
    explicit Sockaddr(const SOCKET_ADDRESS*) noexcept;

    ~Sockaddr() noexcept = default;

    Sockaddr(const Sockaddr&) noexcept;
    Sockaddr& operator=(const Sockaddr&) noexcept;

    Sockaddr(Sockaddr&&) noexcept;
    Sockaddr& operator=(Sockaddr&&) noexcept;

    bool operator==(const Sockaddr&) const noexcept;
    bool operator!=(const Sockaddr&) const noexcept;

    operator bool() const noexcept;

    void set(_In_reads_bytes_(inLength) const SOCKADDR*, size_t inLength) noexcept;
    void set(const SOCKADDR_IN*) noexcept;
    void set(const SOCKADDR_IN6*) noexcept;
    void set(const SOCKADDR_INET*) noexcept;
    void set(const SOCKET_ADDRESS*) noexcept;
    void set(ADDRESS_FAMILY, AddressType) noexcept;

    // setting by string returns a bool indicating if it was able to convert to an address
    [[nodiscard]] bool set_address(PCWSTR) noexcept;
    void set_address(const IN_ADDR*) noexcept;
    void set_address(const IN6_ADDR*) noexcept;
    [[nodiscard]] bool set_address(SOCKET) noexcept;

    void set_port(unsigned short, ByteOrder = ByteOrder::HostOrder) noexcept;
    void set_scope_id(unsigned long) noexcept;
    void set_flowinfo(unsigned long) noexcept;

    [[nodiscard]] bool is_address_any() const noexcept;
    [[nodiscard]] bool is_address_loopback() const noexcept;

    [[nodiscard]] std::wstring write_address() const;
    [[nodiscard]] bool write_address(WCHAR (&address)[IpStringMaxLength]) const noexcept;

    [[nodiscard]] std::wstring write_complete_address(bool trim_scope = false) const;
    [[nodiscard]] bool write_complete_address(WCHAR (&address)[IpStringMaxLength], bool trim_scope = false) const noexcept;

    [[nodiscard]] int length() const noexcept;
    [[nodiscard]] unsigned short port() const noexcept;
    [[nodiscard]] short family() const noexcept;
    [[nodiscard]] unsigned long flowinfo() const noexcept;
    [[nodiscard]] unsigned long scope_id() const noexcept;

    // returns non-const from const method for API compat
    [[nodiscard]] SOCKADDR* sockaddr() const noexcept;
    [[nodiscard]] SOCKADDR_IN* sockaddr_in() const noexcept;
    [[nodiscard]] SOCKADDR_IN6* sockaddr_in6() const noexcept;
    [[nodiscard]] SOCKADDR_INET* sockaddr_inet() const noexcept;
    [[nodiscard]] IN_ADDR* in_addr() const noexcept;
    [[nodiscard]] IN6_ADDR* in6_addr() const noexcept;

private:
    static constexpr size_t m_saddrSize = sizeof(SOCKADDR_INET);

    SOCKADDR_INET m_saddr;
};

/*static*/ inline std::vector<Sockaddr> Sockaddr::ResolveName(PCWSTR name)
{
    ADDRINFOW* addrResult = nullptr;
    auto freeAddrInfoOnExit = wil::scope_exit([&]() noexcept {
        if (addrResult)
            ::FreeAddrInfoW(addrResult);
    });

    std::vector<Sockaddr> returnAddrs;
    if (0 == ::GetAddrInfoW(name, nullptr, nullptr, &addrResult))
    {
        for (auto* addrinfo = addrResult; addrinfo != nullptr; addrinfo = addrinfo->ai_next)
        {
            returnAddrs.emplace_back(addrinfo->ai_addr, addrinfo->ai_addrlen);
        }
    }
    else
    {
        THROW_WIN32_MSG(WSAGetLastError(), "GetAddrInfoW");
    }

    return returnAddrs;
}

inline Sockaddr::Sockaddr(short family, AddressType type) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    m_saddr.si_family = family;

    if (AddressType::Loopback == type)
    {
        if (AF_INET == family)
        {
            auto* const in4 = reinterpret_cast<SOCKADDR_IN*>(&m_saddr);
            const auto port = in4->sin_port;
            ::ZeroMemory(&m_saddr, m_saddrSize);

            in4->sin_family = AF_INET;
            in4->sin_port = port;
            in4->sin_addr.S_un.S_addr = 0x0100007f; // htons(INADDR_LOOPBACK)
        }
        else if (AF_INET6 == family)
        {
            auto* const in6 = reinterpret_cast<SOCKADDR_IN6*>(&m_saddr);
            const auto port = in6->sin6_port;
            ::ZeroMemory(&m_saddr, m_saddrSize);

            in6->sin6_family = AF_INET6;
            in6->sin6_port = port;
            in6->sin6_addr.s6_bytes[15] = 1; // IN6ADDR_LOOPBACK_INIT
        }
        else
        {
            FAIL_FAST_MSG("Sockaddr: unknown family creating loopback sockaddr");
        }
    }
}

inline Sockaddr::Sockaddr(_In_reads_bytes_(inLength) const SOCKADDR* inAddr, size_t inLength) noexcept
{
    const auto length = inLength < m_saddrSize ? inLength : m_saddrSize;

    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN));
}

inline Sockaddr::Sockaddr(const SOCKADDR_IN* inAddr) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN));
}

inline Sockaddr::Sockaddr(const SOCKADDR_IN6* inAddr) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN6));
}

inline Sockaddr::Sockaddr(const SOCKADDR_INET* inAddr) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    if (AF_INET == inAddr->si_family)
    {
        ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN));
    }
    else
    {
        ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN6));
    }
}

inline Sockaddr::Sockaddr(const SOCKET_ADDRESS* inAddr) noexcept
{
    const auto length = static_cast<size_t>(inAddr->iSockaddrLength) <= m_saddrSize ? inAddr->iSockaddrLength : m_saddrSize;

    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr->lpSockaddr, length);
}

inline Sockaddr::Sockaddr(const Sockaddr& other) noexcept
{
    ::CopyMemory(&m_saddr, &other.m_saddr, m_saddrSize);
}

inline Sockaddr& Sockaddr::operator=(const Sockaddr& other) noexcept
{
    ::CopyMemory(&m_saddr, &other.m_saddr, m_saddrSize);
    return *this;
}

inline Sockaddr::Sockaddr(Sockaddr&& other) noexcept
{
    ::CopyMemory(&m_saddr, &other.m_saddr, m_saddrSize);
    ::ZeroMemory(&other.m_saddr, m_saddrSize);
}

inline Sockaddr& Sockaddr::operator=(Sockaddr&& other) noexcept
{
    ::CopyMemory(&m_saddr, &other.m_saddr, m_saddrSize);
    ::ZeroMemory(&other.m_saddr, m_saddrSize);
    return *this;
}

inline bool Sockaddr::operator==(const Sockaddr& other) const noexcept
{
    return (0 == ::memcmp(&m_saddr, &other.m_saddr, m_saddrSize));
}

inline bool Sockaddr::operator!=(const Sockaddr& other) const noexcept
{
    return !(*this == other);
}

inline bool Sockaddr::set_address(SOCKET s) noexcept
{
    auto namelen = static_cast<int>(length());
    return (0 == ::getsockname(s, sockaddr(), &namelen));
}

inline Sockaddr::operator bool() const noexcept
{
    return *this != Sockaddr{};
}

inline void Sockaddr::set(_In_reads_bytes_(inLength) const SOCKADDR* inAddr, size_t inLength) noexcept
{
    const auto length = inLength <= m_saddrSize ? inLength : m_saddrSize;

    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr, length);
}

inline void Sockaddr::set(const SOCKADDR_IN* inAddr) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN));
}

inline void Sockaddr::set(const SOCKADDR_IN6* inAddr) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN6));
}

inline void Sockaddr::set(const SOCKADDR_INET* inAddr) noexcept
{
    ::ZeroMemory(&m_saddr, m_saddrSize);
    if (AF_INET == inAddr->si_family)
    {
        ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN));
    }
    else
    {
        ::CopyMemory(&m_saddr, inAddr, sizeof(SOCKADDR_IN6));
    }
}

inline void Sockaddr::set(const SOCKET_ADDRESS* inAddr) noexcept
{
    const auto length = static_cast<size_t>(inAddr->iSockaddrLength) ? inAddr->iSockaddrLength : m_saddrSize;

    ::ZeroMemory(&m_saddr, m_saddrSize);
    ::CopyMemory(&m_saddr, inAddr->lpSockaddr, length);
}

inline void Sockaddr::set(ADDRESS_FAMILY family, AddressType type) noexcept
{
    Sockaddr temp(family, type);
    *this = temp;
}

inline bool Sockaddr::is_address_any() const noexcept
{
    const Sockaddr any_addr(m_saddr.si_family, AddressType::Any);
    return 0 == ::memcmp(&any_addr.m_saddr, &m_saddr, m_saddrSize);
}

inline bool Sockaddr::is_address_loopback() const noexcept
{
    const Sockaddr loop_addr(m_saddr.si_family, AddressType::Loopback);
    return 0 == ::memcmp(&loop_addr.m_saddr, &m_saddr, m_saddrSize);
}

inline bool Sockaddr::set_address(PCWSTR addr) noexcept
{
    ADDRINFOW addr_hints;
    ::ZeroMemory(&addr_hints, sizeof(ADDRINFOW));
    addr_hints.ai_flags = AI_NUMERICHOST;

    ADDRINFOW* addr_result = nullptr;
    if (0 == GetAddrInfoW(addr, nullptr, &addr_hints, &addr_result))
    {
        set(addr_result->ai_addr, addr_result->ai_addrlen);
        ::FreeAddrInfoW(addr_result);
        return true;
    }

    return false;
}

inline void Sockaddr::set_address(const IN_ADDR* inAddr) noexcept
{
    m_saddr.si_family = AF_INET;
    auto* const addr_in = reinterpret_cast<SOCKADDR_IN*>(&m_saddr);
    addr_in->sin_addr.S_un.S_addr = inAddr->S_un.S_addr;
}

inline void Sockaddr::set_address(const IN6_ADDR* inAddr) noexcept
{
    m_saddr.si_family = AF_INET6;
    auto* const addr_in6 = reinterpret_cast<SOCKADDR_IN6*>(&m_saddr);
    addr_in6->sin6_addr = *inAddr;
}

inline void Sockaddr::set_port(unsigned short port, ByteOrder byteOrder) noexcept
{
    auto* const addr_in = reinterpret_cast<SOCKADDR_IN*>(&m_saddr);
    addr_in->sin_port = byteOrder == ByteOrder::HostOrder ? htons(port) : port;
}

inline void Sockaddr::set_scope_id(unsigned long scopeId) noexcept
{
    if (AF_INET6 == m_saddr.si_family)
    {
        auto* const addr_in6 = reinterpret_cast<SOCKADDR_IN6*>(&m_saddr);
        addr_in6->sin6_scope_id = scopeId;
    }
}

inline void Sockaddr::set_flowinfo(unsigned long flowinfo) noexcept
{
    if (AF_INET6 == m_saddr.si_family)
    {
        auto* const addr_in6 = reinterpret_cast<SOCKADDR_IN6*>(&m_saddr);
        addr_in6->sin6_flowinfo = flowinfo;
    }
}

inline std::wstring Sockaddr::write_address() const
{
    WCHAR result[IpStringMaxLength];
    (void)write_address(result);
    result[IpStringMaxLength - 1] = L'\0';
    return result;
}

inline bool Sockaddr::write_address(WCHAR (&address)[IpStringMaxLength]) const noexcept
{
    ::ZeroMemory(address, IpStringMaxLength * sizeof(WCHAR));

    const auto* const addr =
        AF_INET == m_saddr.si_family ? reinterpret_cast<PVOID>(in_addr()) : reinterpret_cast<PVOID>(in6_addr());
    return (nullptr != ::InetNtopW(m_saddr.si_family, addr, address, IpStringMaxLength));
}

inline std::wstring Sockaddr::write_complete_address(bool trim_scope) const
{
    WCHAR result[IpStringMaxLength];
    (void)write_complete_address(result, trim_scope);
    result[IpStringMaxLength - 1] = L'\0';
    return result;
}

inline bool Sockaddr::write_complete_address(WCHAR (&address)[IpStringMaxLength], bool trim_scope) const noexcept
{
    ::ZeroMemory(address, IpStringMaxLength);

    DWORD addressLength = IpStringMaxLength;
    if (0 == ::WSAAddressToStringW(sockaddr(), static_cast<DWORD>(m_saddrSize), nullptr, address, &addressLength))
    {
        if (family() == AF_INET6 && trim_scope)
        {
            auto* const end = address + addressLength;
            auto* scope_ptr = std::find(address, end, L']');
            if (scope_ptr != end)
            {
                const WCHAR* move_ptr = std::find(address, end, L']');
                if (move_ptr != end)
                {
                    while (move_ptr != end)
                    {
                        *scope_ptr = *move_ptr;
                        ++scope_ptr;
                        ++move_ptr;
                    }
                }
                else
                {
                    // no port was appended
                    while (scope_ptr != end)
                    {
                        *scope_ptr = L'\0';
                        ++scope_ptr;
                    }
                }
            }
        }

        return true;
    }

    return false;
}

inline int Sockaddr::length() const noexcept
{
    return static_cast<int>(m_saddrSize);
}

inline short Sockaddr::family() const noexcept
{
    return m_saddr.si_family;
}

inline unsigned short Sockaddr::port() const noexcept
{
    const auto* const addr_in = reinterpret_cast<const SOCKADDR_IN*>(&m_saddr);
    return ntohs(addr_in->sin_port);
}

inline unsigned long Sockaddr::flowinfo() const noexcept
{
    if (AF_INET6 == m_saddr.si_family)
    {
        const auto* const addr_in6 = reinterpret_cast<const SOCKADDR_IN6*>(&m_saddr);
        return addr_in6->sin6_flowinfo;
    }
    return 0;
}

inline unsigned long Sockaddr::scope_id() const noexcept
{
    if (AF_INET6 == m_saddr.si_family)
    {
        const auto* const addr_in6 = reinterpret_cast<const SOCKADDR_IN6*>(&m_saddr);
        return addr_in6->sin6_scope_id;
    }
    return 0;
}

inline SOCKADDR* Sockaddr::sockaddr() const noexcept
{
    return const_cast<SOCKADDR*>(reinterpret_cast<const SOCKADDR*>(&m_saddr));
}

inline SOCKADDR_IN* Sockaddr::sockaddr_in() const noexcept
{
    return const_cast<SOCKADDR_IN*>(reinterpret_cast<const SOCKADDR_IN*>(&m_saddr));
}

inline SOCKADDR_IN6* Sockaddr::sockaddr_in6() const noexcept
{
    return const_cast<SOCKADDR_IN6*>(reinterpret_cast<const SOCKADDR_IN6*>(&m_saddr));
}

inline SOCKADDR_INET* Sockaddr::sockaddr_inet() const noexcept
{
    return const_cast<SOCKADDR_INET*>(&m_saddr);
}

inline IN_ADDR* Sockaddr::in_addr() const noexcept
{
    const auto* const addr_in = reinterpret_cast<const SOCKADDR_IN*>(&m_saddr);
    return const_cast<IN_ADDR*>(&addr_in->sin_addr);
}

inline IN6_ADDR* Sockaddr::in6_addr() const noexcept
{
    const auto* const addr_in6 = reinterpret_cast<const SOCKADDR_IN6*>(&m_saddr);
    return const_cast<IN6_ADDR*>(&addr_in6->sin6_addr);
}

} // namespace multipath
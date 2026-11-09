// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <wil/network.h>

// Temporary local implementation of socket_address::reset_complete_address_nothrow.
// Once that member is published in wil/network.h and packages.config moves to that WIL version,
// delete this header and call the member directly from TcpipEvents.cpp.
//
// Parses the output of socket_address::format_complete_address: an IP address with an optional port
// and, for IPv6, an optional scope id. For example: 192.0.2.1:443 or [fe80::1%5]:443
[[nodiscard]] inline HRESULT
ResetCompleteAddressNothrow(wil::network::socket_address& socket_address, PCWSTR address) noexcept
{
	USHORT port{};

	socket_address.reset(AF_INET);
	constexpr BOOLEAN strict_string{TRUE};
	if (RtlIpv4StringToAddressExW(address, strict_string, socket_address.in_addr(), &port) == 0)
	{
		// RtlIpv4StringToAddressExW returns the port in network byte order, as stored in the sockaddr
		socket_address.sockaddr_in()->sin_port = port;
		return S_OK;
	}

	ULONG scope_id{};
	socket_address.reset(AF_INET6);
	if (RtlIpv6StringToAddressExW(address, socket_address.in6_addr(), &scope_id, &port) == 0)
	{
		// RtlIpv6StringToAddressExW returns the port in network byte order, as stored in the sockaddr
		socket_address.sockaddr_in6()->sin6_port = port;
		// written directly because socket_address::set_scope_id byte-swaps; sin6_scope_id is in host byte order
		socket_address.sockaddr_in6()->sin6_scope_id = scope_id;
		return S_OK;
	}

	socket_address.reset();
	return E_INVALIDARG;
}

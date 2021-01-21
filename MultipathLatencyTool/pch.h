#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.Connectivity.h>

#include <wil/result.h>
#include <wil/resource.h>

#include <algorithm>
#include <array>
#include <memory>
#include <iostream>
#include <vector>
#include <functional>
#include <utility>
#include <tuple>
#include <string>
#include <string_view>

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <Windows.h>

// where a rule's package ID (its app-container SID) came from
enum class PackageIdSource : uint8_t
{
	// the rule's own package ID field
	Rule,
	// derived from the rule's package family name, because the rule has no package ID
	DerivedFromFamilyName
};

// the app package a rule applies to; copied into findings so they stay correct when the rules are reordered
struct RulePackageIdentity
{
	// the app-container SID; nullopt when the rule has none and it could not be derived from the family name
	std::optional<std::wstring> packageId;
	PackageIdSource packageIdSource{PackageIdSource::Rule};
	// nullopt when the rule has no package family name
	std::optional<std::wstring> packageFamilyName;
	// the failure deriving the package ID from the family name; S_OK otherwise
	HRESULT packageIdError{S_OK};
};

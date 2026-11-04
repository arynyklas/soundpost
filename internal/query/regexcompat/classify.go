// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"soundpost/internal/query/profile"
	u123 "soundpost/third_party/regex/go123/unicode"
	u124 "soundpost/third_party/regex/go124/unicode"
	u126 "soundpost/third_party/regex/go126/unicode"
)

// Classification follows the locked compiler edition, not the host toolchain.
func IsLetter(p profile.Profile, r rune) (bool, error) {
	e, err := selectEdition(p)
	if err != nil {
		return false, err
	}
	switch e {
	case 1:
		return u123.IsLetter(r), nil
	case 2:
		return u124.IsLetter(r), nil
	default:
		return u126.IsLetter(r), nil
	}
}
func IsDigit(p profile.Profile, r rune) (bool, error) {
	e, err := selectEdition(p)
	if err != nil {
		return false, err
	}
	switch e {
	case 1:
		return u123.IsDigit(r), nil
	case 2:
		return u124.IsDigit(r), nil
	default:
		return u126.IsDigit(r), nil
	}
}
func IsSpace(p profile.Profile, r rune) (bool, error) {
	e, err := selectEdition(p)
	if err != nil {
		return false, err
	}
	switch e {
	case 1:
		return u123.IsSpace(r), nil
	case 2:
		return u124.IsSpace(r), nil
	default:
		return u126.IsSpace(r), nil
	}
}

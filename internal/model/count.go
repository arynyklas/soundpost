// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"strconv"
)

type AbsoluteBucket uint64

func (v AbsoluteBucket) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}
func (v *AbsoluteBucket) UnmarshalJSON(raw []byte) error {
	s, err := parseDecimal(raw, false)
	if err != nil {
		return err
	}
	n, err := strconv.ParseUint(s, 10, 64)
	*v = AbsoluteBucket(n)
	return err
}

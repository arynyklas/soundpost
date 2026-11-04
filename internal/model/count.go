// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

type AbsoluteBucket uint64

func (v AbsoluteBucket) MarshalJSON() ([]byte, error) {
	return Uint64(v).MarshalJSON()
}
func (v *AbsoluteBucket) UnmarshalJSON(raw []byte) error {
	var value Uint64
	if err := value.UnmarshalJSON(raw); err != nil {
		return err
	}
	*v = AbsoluteBucket(value)
	return nil
}

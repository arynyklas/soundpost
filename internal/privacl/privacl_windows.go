// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package privacl

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func check(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return ErrNotPrivate
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return ErrNotPrivate // no DACL grants everyone full access
	}
	trusted, err := trustedSIDs(owner)
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // a deny entry or an audit entry grants nothing
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		known := false
		for _, t := range trusted {
			if windows.EqualSid(sid, t) {
				known = true
				break
			}
		}
		if !known {
			return ErrNotPrivate
		}
	}
	return nil
}

// trustedSIDs are the principals that can already read anything the owner can:
// the owner, the user this process runs as, SYSTEM, the Administrators group and
// CREATOR OWNER (which resolves to the owner on a child object).
func trustedSIDs(owner *windows.SID) ([]*windows.SID, error) {
	out := []*windows.SID{owner}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	out = append(out, user.User.Sid)
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinCreatorOwnerSid} {
		s, err := windows.CreateWellKnownSid(k)
		if err != nil {
			return nil, errors.New("privacl: well-known SID unavailable")
		}
		out = append(out, s)
	}
	return out, nil
}

func restrict(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sids := []*windows.SID{user.User.Sid}
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		s, err := windows.CreateWellKnownSid(k)
		if err != nil {
			return err
		}
		sids = append(sids, s)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for i, s := range sids {
		trusteeType := windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_WELL_KNOWN_GROUP)
		if i == 0 {
			trusteeType = windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_USER)
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: trusteeType, TrusteeValue: windows.TrusteeValueFromSID(s)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

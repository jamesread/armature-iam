package store

import "errors"

var (
	ErrNoSuperuser     = errors.New("refusing to leave the system without a superuser")
	ErrSystemRole      = errors.New("cannot modify system role")
	ErrSystemGroup     = errors.New("cannot modify system group")
	ErrRenameSystemRole = errors.New("cannot rename system role")
)

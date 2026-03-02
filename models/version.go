package models

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version represents a semantic version (e.g., v1.0.0).
type Version struct {
	Major uint32
	Minor uint32
	Patch uint32
}

// NewVersion creates a new Version with the given components.
func NewVersion(major, minor, patch uint32) Version {
	return Version{Major: major, Minor: minor, Patch: patch}
}

// ParseVersion parses a version string (e.g., "v1.0.0" or "1.0.0").
func ParseVersion(s string) (Version, error) {
	if s == "" {
		return Version{}, errors.New("empty version string")
	}

	// Remove 'v' prefix if present
	s = strings.TrimPrefix(s, "v")

	const semverParts = 3
	parts := strings.Split(s, ".")
	if len(parts) != semverParts {
		return Version{}, fmt.Errorf("expected %d parts, got %d: %s", semverParts, len(parts), s)
	}

	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return Version{}, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return Version{}, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	patch, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return Version{}, fmt.Errorf("invalid patch version: %s", parts[2])
	}

	return Version{
		Major: uint32(major),
		Minor: uint32(minor),
		Patch: uint32(patch),
	}, nil
}

// String returns the version string with 'v' prefix (e.g., "v1.0.0").
func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare compares two versions. Returns:
// -1 if v < other
//
//	0 if v == other
//	1 if v > other
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// IsZero returns true if the version has not been set.
func (v Version) IsZero() bool {
	return v.Major == 0 && v.Minor == 0 && v.Patch == 0
}

// Equal returns true if the versions are equal.
func (v Version) Equal(other Version) bool {
	return v.Compare(other) == 0
}

// Less returns true if v is less than other.
func (v Version) Less(other Version) bool {
	return v.Compare(other) < 0
}

package data

import "github.com/a-h/nvdnotifier/nvd"

type GetLastModifiedMetadata func() (m nvd.Meta, found bool, err error)
type PutLastModifiedMetadata func(nvd.Meta) error

type GetLastRecentMetadata func() (m nvd.Meta, found bool, err error)
type PutLastRecentMetadata func(nvd.Meta) error

type GetNotified func(cve nvd.CVEItem) (bool, error)
type PutNotified func(cve nvd.CVEItem) error

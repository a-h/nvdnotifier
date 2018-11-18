package checker

import (
	"fmt"
	"sync"

	"github.com/a-h/nvdnotifier/data"
	"github.com/a-h/nvdnotifier/logger"

	"github.com/a-h/nvdnotifier/nvd"
)

const pkg = "nvdnotifier"

// A ModifiedMetadataGetter gets the metadata for modified CVEs.
// The metadata contains the hash of the file and the date it was last updated etc.
type ModifiedMetadataGetter func() (nvd.Meta, error)

// A ModifiedGetter gets the data for CVEs which have been recently modified.
type ModifiedGetter func() (d nvd.Data, hash string, err error)

// A RecentMetadataGetter gets the metadata for recently creaated CVEs.
type RecentMetadataGetter func() (nvd.Meta, error)

// A RecentGetter gets the data for CVEs which have been recently created.
type RecentGetter func() (d nvd.Data, hash string, err error)

// A Notifier notifies about a matching vulnerability.
type Notifier func(cve nvd.CVEItem) error

// An IncludeFilter filters out CVEs which don't match.
type IncludeFilter func(cve nvd.CVEItem) bool

// IncludeGo in the search.
func IncludeGo(cve nvd.CVEItem) (include bool) {
	for _, vd := range cve.CVE.Affects.Vendor.VendorData {
		if vd.VendorName != "golang" {
			continue
		}
		for _, pd := range vd.Product.ProductData {
			if pd.ProductName == "go" {
				return true
			}
		}
	}
	return false
}

// IncludeNodeJS in the search.
func IncludeNodeJS(cve nvd.CVEItem) (include bool) {
	for _, vd := range cve.CVE.Affects.Vendor.VendorData {
		if vd.VendorName != "nodejs" {
			continue
		}
		for _, pd := range vd.Product.ProductData {
			if pd.ProductName == "node.js" || pd.ProductName == "nodejs" {
				return true
			}
		}
	}
	return false
}

// New creates a new checker.
func New(mmg ModifiedMetadataGetter, gm ModifiedGetter,
	glmm data.GetLastModifiedMetadata, plmm data.PutLastModifiedMetadata,
	rmg RecentMetadataGetter, rg RecentGetter,
	glrm data.GetLastRecentMetadata, plrm data.PutLastRecentMetadata,
	hbn data.GetNotified, man data.PutNotified,
	notifiers []Notifier, include ...IncludeFilter) Checker {
	return Checker{
		GetModifiedMetadata:     mmg,
		GetModified:             gm,
		GetLastModifiedMetadata: glmm,
		PutLastModifiedMetadata: plmm,
		GetRecentMetadata:       rmg,
		GetRecent:               rg,
		GetLastRecentMetadata:   glrm,
		PutLastRecentMetadata:   plrm,
		HasBeenNotified:         hbn,
		MarkAsNotified:          man,
		Notifiers:               notifiers,
		Include:                 include,
	}
}

// A Checker checks for the latest vulnerabilities, keeping a record of the vulnerabilities it has previously
// processed.
type Checker struct {
	GetModifiedMetadata ModifiedMetadataGetter
	GetModified         ModifiedGetter
	GetRecentMetadata   RecentMetadataGetter
	GetRecent           RecentGetter

	// GetLastModifiedMetadata gets the last "updated" metadata from the database.
	GetLastModifiedMetadata data.GetLastModifiedMetadata
	PutLastModifiedMetadata data.PutLastModifiedMetadata
	// GetLastRecentMetadata gets the last "recent" metadata from the database.
	GetLastRecentMetadata data.GetLastRecentMetadata
	PutLastRecentMetadata data.PutLastRecentMetadata

	HasBeenNotified data.GetNotified
	MarkAsNotified  data.PutNotified
	Notifiers       []Notifier
	Include         []IncludeFilter
}

// RecentOrUpdated returns any new or updated CVEs which match the filters.
// It also executes any notifications.
func (c Checker) RecentOrUpdated() (items []nvd.CVEItem, err error) {
	var wg sync.WaitGroup

	var rd nvd.Data
	var rdErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		rd, rdErr = getIfRequired(c.GetLastRecentMetadata, c.GetRecentMetadata, c.GetRecent, c.PutLastRecentMetadata)
	}()

	var md nvd.Data
	var mdErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		md, mdErr = getIfRequired(c.GetLastModifiedMetadata, c.GetModifiedMetadata, c.GetModified, c.PutLastModifiedMetadata)
	}()

	wg.Wait()

	if rdErr != nil {
		err = fmt.Errorf("error getting recent data: %v", rdErr)
		return
	}
	if mdErr != nil {
		err = fmt.Errorf("error getting modified data: %v", mdErr)
		return
	}

	for _, item := range rd.CVEItems {
		if matchesAnyFilter(item, c.Include) {
			items = append(items, item)
		}
	}
	for _, item := range md.CVEItems {
		if matchesAnyFilter(item, c.Include) {
			items = append(items, item)
		}
	}
	items, err = removeDuplicateItems(items)
	if err != nil {
		return
	}
	items, err = removeNotifiedItems(items, c.HasBeenNotified)
	if err != nil {
		return
	}
	for _, item := range items {
		for _, n := range c.Notifiers {
			if nErr := n(item); nErr != nil {
				err = fmt.Errorf("failed to notifify %v: %v", item.CVE.CVEDataMeta.ID, nErr)
				return
			}
		}
		if nErr := c.MarkAsNotified(item); nErr != nil {
			err = fmt.Errorf("failed to mark %v as notified: %v", item.CVE.CVEDataMeta.ID, nErr)
			return
		}
	}
	return
}

func removeDuplicateItems(input []nvd.CVEItem) (output []nvd.CVEItem, err error) {
	output = []nvd.CVEItem{}
	previous := map[string]struct{}{}
	for _, item := range input {
		hash, hErr := item.Hash()
		if hErr != nil {
			err = fmt.Errorf("error creating hash of CVE %v: %v", item.CVE.CVEDataMeta.ID, hErr)
			return
		}
		if _, alreadySeen := previous[hash]; alreadySeen {
			continue
		}
		output = append(output, item)
		previous[hash] = struct{}{}
	}
	return
}

func removeNotifiedItems(input []nvd.CVEItem, hasBeenNotified data.GetNotified) (output []nvd.CVEItem, err error) {
	output = []nvd.CVEItem{}
	for _, item := range input {
		notified, nErr := hasBeenNotified(item)
		if nErr != nil {
			err = fmt.Errorf("error checking for notification: %v", nErr)
			return
		}
		if notified {
			continue
		}
		output = append(output, item)
	}
	return
}

func getIfRequired(getLastMetadata func() (m nvd.Meta, found bool, err error),
	getCurrentMetadata func() (nvd.Meta, error),
	getCurrentData func() (nvd.Data, string, error),
	putLastMetadata func(nvd.Meta) error,
) (d nvd.Data, err error) {
	m, ok, err := hasBeenUpdated(getLastMetadata, getCurrentMetadata)
	logger.For(pkg, "getIfRequired").WithField("hasBeenUpdated", ok).Info("has been updated")
	if err != nil {
		return
	}
	if !ok {
		return
	}
	d, hash, err := getCurrentData()
	if err != nil {
		err = fmt.Errorf("failed to get recent CVEs: %v", err)
		return
	}
	if m.SHA256 != hash {
		err = fmt.Errorf("metadata hash (%v) doesn't match data hash (%v)", m.SHA256, hash)
		return
	}
	err = putLastMetadata(m)
	return
}

func hasBeenUpdated(getLastMetadata func() (m nvd.Meta, found bool, err error),
	getCurrentMetadata func() (m nvd.Meta, err error)) (m nvd.Meta, updated bool, err error) {
	old, _, err := getLastMetadata()
	if err != nil {
		logger.For(pkg, "hasBeenUpdated").WithError(err).Error("failed to get last metadata")
		return
	}
	m, err = getCurrentMetadata()
	if err != nil {
		logger.For(pkg, "hasBeenUpdated").WithError(err).Error("failed to get current metadata")
		return
	}
	logger.For(pkg, "hasBeenUpdated").WithField("updated", updated).
		WithField("previous", old).
		WithField("current", m).
		Info("previous and current hashes acquired")
	updated = m.SHA256 != old.SHA256
	return
}

func matchesAnyFilter(item nvd.CVEItem, filters []IncludeFilter) bool {
	for _, f := range filters {
		if f(item) {
			return true
		}
	}
	return false
}

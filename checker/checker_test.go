package checker

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/a-h/nvdnotifier/nvd"
)

func mockCVE(id, vendor, product string) nvd.CVE {
	return nvd.CVE{
		CVEDataMeta: nvd.DataMeta{
			ID: id,
		},
		Affects: nvd.Affects{
			Vendor: nvd.Vendor{
				VendorData: []nvd.VendorData{
					nvd.VendorData{
						VendorName: vendor,
						Product: nvd.Product{
							ProductData: []nvd.ProductData{
								nvd.ProductData{
									ProductName: product,
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestChecker(t *testing.T) {
	modifiedMetadataDefault := nvd.Meta{
		SHA256: "sha256_value_modified",
	}
	getLastModifiedMetadataSuccess := func() (m nvd.Meta, found bool, err error) {
		m = modifiedMetadataDefault
		found = true
		return
	}
	modifiedMetadataGetterSuccess := func() (nvd.Meta, error) {
		return modifiedMetadataDefault, nil
	}
	modifiedDataDefault := nvd.Data{
		CVEItems: []nvd.CVEItem{
			nvd.CVEItem{
				CVE: mockCVE("cve_golang_1_modified", "golang", "go"),
			},
		},
	}
	modifiedGetterSuccess := func() (d nvd.Data, hash string, err error) {
		return modifiedDataDefault, "sha256_value_modified", nil
	}
	putLastModifiedMetadataSuccess := func(m nvd.Meta) error {
		return nil
	}

	recentMetadataDefault := nvd.Meta{
		SHA256: "sha256_value_recent",
	}
	getLastRecentMetadataSuccess := func() (m nvd.Meta, found bool, err error) {
		m = recentMetadataDefault
		found = true
		return
	}
	recentMetadataGetterSuccess := func() (nvd.Meta, error) {
		return recentMetadataDefault, nil
	}
	recentDataDefault := nvd.Data{
		CVEItems: []nvd.CVEItem{
			nvd.CVEItem{
				CVE: mockCVE("cve_golang_1_recent", "golang", "go"),
			},
		},
	}
	recentGetterSuccess := func() (d nvd.Data, hash string, err error) {
		return recentDataDefault, "sha256_value_recent", nil
	}
	putLastRecentMetadataSuccess := func(m nvd.Meta) error {
		return nil
	}

	isNotifiedFalse := func(cve nvd.CVEItem) (bool, error) { return false, nil }
	isNotifiedTrue := func(cve nvd.CVEItem) (bool, error) { return true, nil }
	putNotifiedSuccess := func(cve nvd.CVEItem) error { return nil }

	databaseErr := fmt.Errorf("unknown database err")

	tests := []struct {
		name                     string
		getLastModifiedMetadata  func() (m nvd.Meta, found bool, err error)
		modifiedMetadataGetter   ModifiedMetadataGetter
		modifiedGetter           ModifiedGetter
		putLastModifiedMetadata  func(m nvd.Meta) error
		getLastRecentMetadata    func() (m nvd.Meta, found bool, err error)
		recentMetadataGetter     RecentMetadataGetter
		recentGetter             RecentGetter
		putLastRecentMetadata    func(m nvd.Meta) error
		isNotified               func(cve nvd.CVEItem) (bool, error)
		putNotified              func(cve nvd.CVEItem) error
		filters                  []IncludeFilter
		expectedNotificationCVEs []string
		expectedErr              error
	}{
		{
			name: "if there's no 'last' modified metadata stored, the new metadata is used and data is downloaded",
			getLastModifiedMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			modifiedMetadataGetter:   modifiedMetadataGetterSuccess,
			modifiedGetter:           modifiedGetterSuccess,
			putLastModifiedMetadata:  putLastModifiedMetadataSuccess,
			getLastRecentMetadata:    getLastRecentMetadataSuccess,
			recentMetadataGetter:     recentMetadataGetterSuccess,
			recentGetter:             recentGetterSuccess,
			putLastRecentMetadata:    putLastRecentMetadataSuccess,
			isNotified:               isNotifiedFalse,
			putNotified:              putNotifiedSuccess,
			filters:                  []IncludeFilter{IncludeGo},
			expectedNotificationCVEs: []string{"cve_golang_1_modified"},
			expectedErr:              nil,
		},
		{
			name: "if there's no 'last' recent metadata stored, the new metadata is used and data is downloaded",
			getLastModifiedMetadata: getLastModifiedMetadataSuccess,
			modifiedMetadataGetter:  modifiedMetadataGetterSuccess,
			modifiedGetter:          modifiedGetterSuccess,
			putLastModifiedMetadata: putLastModifiedMetadataSuccess,
			getLastRecentMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			recentMetadataGetter:     recentMetadataGetterSuccess,
			recentGetter:             recentGetterSuccess,
			putLastRecentMetadata:    putLastRecentMetadataSuccess,
			isNotified:               isNotifiedFalse,
			putNotified:              putNotifiedSuccess,
			filters:                  []IncludeFilter{IncludeGo},
			expectedNotificationCVEs: []string{"cve_golang_1_recent"},
			expectedErr:              nil,
		},
		{
			name: "if no changes have happened to either metadata, nothing is notified",
			getLastModifiedMetadata:  getLastModifiedMetadataSuccess,
			modifiedMetadataGetter:   modifiedMetadataGetterSuccess,
			modifiedGetter:           modifiedGetterSuccess,
			putLastModifiedMetadata:  putLastModifiedMetadataSuccess,
			getLastRecentMetadata:    getLastRecentMetadataSuccess,
			recentMetadataGetter:     recentMetadataGetterSuccess,
			recentGetter:             recentGetterSuccess,
			putLastRecentMetadata:    putLastRecentMetadataSuccess,
			isNotified:               isNotifiedFalse,
			putNotified:              putNotifiedSuccess,
			filters:                  []IncludeFilter{IncludeGo},
			expectedNotificationCVEs: []string{},
			expectedErr:              nil,
		},
		{
			name: "if modified and recents contain duplicates, they are filtered",
			getLastModifiedMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			modifiedMetadataGetter: modifiedMetadataGetterSuccess,
			modifiedGetter: func() (d nvd.Data, hash string, err error) {
				d = nvd.Data{
					CVEItems: []nvd.CVEItem{
						nvd.CVEItem{
							CVE: mockCVE("duplicate_cve", "golang", "go"),
						},
					},
				}
				return d, "sha256_value_modified", nil
			},
			putLastModifiedMetadata: putLastModifiedMetadataSuccess,
			getLastRecentMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			recentMetadataGetter: recentMetadataGetterSuccess,
			recentGetter: func() (d nvd.Data, hash string, err error) {
				d = nvd.Data{
					CVEItems: []nvd.CVEItem{
						nvd.CVEItem{
							CVE: mockCVE("duplicate_cve", "golang", "go"),
						},
					},
				}
				return d, "sha256_value_recent", nil
			},
			putLastRecentMetadata:    putLastRecentMetadataSuccess,
			isNotified:               isNotifiedFalse,
			putNotified:              putNotifiedSuccess,
			filters:                  []IncludeFilter{IncludeGo},
			expectedNotificationCVEs: []string{"duplicate_cve"},
			expectedErr:              nil,
		},
		{
			name: "if no data matches the filter, no notifications are made",
			getLastModifiedMetadata: getLastModifiedMetadataSuccess,
			modifiedMetadataGetter:  modifiedMetadataGetterSuccess,
			modifiedGetter:          modifiedGetterSuccess,
			putLastModifiedMetadata: putLastModifiedMetadataSuccess,
			getLastRecentMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			recentMetadataGetter:     recentMetadataGetterSuccess,
			recentGetter:             recentGetterSuccess,
			putLastRecentMetadata:    putLastRecentMetadataSuccess,
			isNotified:               isNotifiedFalse,
			putNotified:              putNotifiedSuccess,
			filters:                  []IncludeFilter{IncludeNodeJS},
			expectedNotificationCVEs: []string{},
			expectedErr:              nil,
		},
		{
			name: "if the notifications have already been made, they are not repeated",
			getLastModifiedMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			modifiedMetadataGetter:  modifiedMetadataGetterSuccess,
			modifiedGetter:          modifiedGetterSuccess,
			putLastModifiedMetadata: putLastModifiedMetadataSuccess,
			getLastRecentMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				return
			},
			recentMetadataGetter:     recentMetadataGetterSuccess,
			recentGetter:             recentGetterSuccess,
			putLastRecentMetadata:    putLastRecentMetadataSuccess,
			isNotified:               isNotifiedTrue,
			putNotified:              nil, // Would cause the test to panic if called (which shouldn't happen)
			filters:                  []IncludeFilter{IncludeGo},
			expectedNotificationCVEs: []string{},
			expectedErr:              nil,
		},
		{
			name: "errors reading from the database cause an early exit - modified",
			getLastModifiedMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				err = databaseErr
				return
			},
			getLastRecentMetadata:    getLastRecentMetadataSuccess,
			recentMetadataGetter:     recentMetadataGetterSuccess,
			expectedNotificationCVEs: []string{},
			expectedErr:              fmt.Errorf("error getting modified data: unknown database err"),
		},
		{
			name: "errors reading from the database cause an early exit - recent",
			getLastModifiedMetadata: getLastModifiedMetadataSuccess,
			modifiedMetadataGetter:  modifiedMetadataGetterSuccess,
			getLastRecentMetadata: func() (m nvd.Meta, found bool, err error) {
				found = false
				err = databaseErr
				return
			},
			expectedNotificationCVEs: []string{},
			expectedErr:              fmt.Errorf("error getting recent data: unknown database err"),
		},
	}
	for _, tc := range tests {
		test := tc
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			notifiedCVEs := []string{}
			notifier := func(cve nvd.CVEItem) error {
				notifiedCVEs = append(notifiedCVEs, cve.CVE.CVEDataMeta.ID)
				return nil
			}

			c := New(test.modifiedMetadataGetter, test.modifiedGetter,
				test.getLastModifiedMetadata, test.putLastModifiedMetadata,
				test.recentMetadataGetter, test.recentGetter,
				test.getLastRecentMetadata, test.putLastRecentMetadata,
				test.isNotified, test.putNotified,
				[]Notifier{notifier},
				test.filters...)
			_, err := c.RecentOrUpdated()
			if err != test.expectedErr && err.Error() != test.expectedErr.Error() {
				t.Fatalf("expected err '%v', got '%v'", test.expectedErr, err)
			}
			if !reflect.DeepEqual(notifiedCVEs, test.expectedNotificationCVEs) {
				t.Errorf("expected notifications for %v, got %v", test.expectedNotificationCVEs, notifiedCVEs)
			}
		})
	}
}

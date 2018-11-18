package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/a-h/nvdnotifier/conf"
	"github.com/a-h/nvdnotifier/dynamo"
	"github.com/a-h/nvdnotifier/slack"

	"github.com/a-h/nvdnotifier/logger"

	"github.com/a-h/nvdnotifier/checker"
	"github.com/a-h/nvdnotifier/nvd"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

const pkg = "nvdnotifier"

func main() {
	l := logger.For(pkg, "main")
	c, err := conf.FromEnvironment()
	if err != nil {
		l.WithError(err).Error("invalid configuration")
		return
	}
	if c.RunLocal {
		if err := run(c.DynamoDBRegion, c.MetadataTableName, c.NotificationTableName, c.SlackWebhookURL); err != nil {
			l.WithError(err).Fatal("execution failed")
		}
		return
	}
	h := func(ctx context.Context, e events.CloudWatchEvent) (err error) {
		return run(c.DynamoDBRegion, c.MetadataTableName, c.NotificationTableName, c.SlackWebhookURL)
	}
	lambda.Start(h)
}

func run(region, metadataTableName, notificationTableName, slackWebhookURL string) (err error) {
	logNotifier := func(cve nvd.CVEItem) error {
		logger.For(pkg, "log").WithField("cve", cve.CVE.CVEDataMeta.ID).Info("vulnerability found")
		return nil
	}
	n := slack.NewNotifier(slackWebhookURL)
	slackNotifier := func(cve nvd.CVEItem) error {
		var vendors []string
		var products []string
		for _, vd := range cve.CVE.Affects.Vendor.VendorData {
			vendors = append(vendors, vd.VendorName)
			for _, p := range vd.Product.ProductData {
				products = append(products, fmt.Sprintf("%v", p.ProductName))
			}
		}
		var descs []string
		for _, dd := range cve.CVE.Description.DescriptionData {
			descs = append(descs, dd.Value)
		}
		desc := strings.Join(descs, "\n")
		text := fmt.Sprintf("Vendor %v, Product %v: %v", strings.Join(vendors, ", "), strings.Join(products, ", "), desc)
		m := slack.NewMessage(cve.CVE.CVEDataMeta.ID, text)
		return n.Push(m)
	}
	mds, err := dynamo.NewMetadataStore(region, metadataTableName)
	if err != nil {
		return
	}
	getLastModifiedMetadata := func() (m nvd.Meta, found bool, err error) {
		return mds.Get(nvd.ModifiedMetadataURL)
	}
	putLastModifiedMetadata := func(m nvd.Meta) error {
		return mds.Put(nvd.ModifiedMetadataURL, m)
	}
	getLastRecentMetadata := func() (m nvd.Meta, found bool, err error) {
		return mds.Get(nvd.RecentMetadataURL)
	}
	putLastRecentMetadata := func(m nvd.Meta) error {
		return mds.Put(nvd.RecentMetadataURL, m)
	}
	ns, err := dynamo.NewNotificationStore(region, notificationTableName)
	if err != nil {
		return
	}
	isNotified := func(cve nvd.CVEItem) (ok bool, err error) {
		hash, err := cve.Hash()
		if err != nil {
			return
		}
		_, ok, err = ns.Get(hash)
		return
	}
	putNotified := func(cve nvd.CVEItem) error {
		return ns.Put(cve)
	}
	c := checker.New(nvd.ModifiedMetadata, nvd.Modified,
		getLastModifiedMetadata, putLastModifiedMetadata,
		nvd.RecentMetadata, nvd.Recent,
		getLastRecentMetadata, putLastRecentMetadata,
		isNotified, putNotified,
		[]checker.Notifier{logNotifier, slackNotifier}, checker.IncludeGo, checker.IncludeNodeJS)
	items, err := c.RecentOrUpdated()
	if err != nil {
		return
	}
	logger.For(pkg, "main").WithField("itemCount", len(items)).Info("complete")
	return
}

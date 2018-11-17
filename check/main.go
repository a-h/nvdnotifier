package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/a-h/nvdnotifier/logger"

	"github.com/a-h/nvdnotifier/checker"
	"github.com/a-h/nvdnotifier/nvd"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

const pkg = "nvdnotified"

func handler(ctx context.Context, e events.CloudWatchEvent) (err error) {
	return run()
}

var localFlag = flag.Bool("local", false, "Sets whether the program is being executed locally (not in a Lambda) for testing.")

func main() {
	flag.Parse()
	if *localFlag {
		if err := run(); err != nil {
			log.Fatal(err)
		}
		return
	}
	lambda.Start(handler)
}

func run() (err error) {
	console := func(cve nvd.CVEItem) error {
		fmt.Println(cve.CVE.CVEDataMeta.ID)
		return nil
	}
	getLastModifiedMetadataMock := func() (m nvd.Meta, found bool, err error) {
		found = false
		return
	}
	putLastModifiedMetadataMock := func(m nvd.Meta) error {
		fmt.Printf("Mock: pretending to store modified metadata: '%+v'\n", m)
		return nil
	}
	getLastRecentMetadataMock := func() (m nvd.Meta, found bool, err error) {
		found = false
		return
	}
	putLastRecentMetadataMock := func(m nvd.Meta) error {
		fmt.Printf("Mock: pretending to store recent metadata: '%+v'\n", m)
		return nil
	}
	isNotifiedMock := func(cve nvd.CVEItem) (bool, error) {
		return false, nil
	}
	putNotifiedMock := func(cve nvd.CVEItem) error {
		return nil
	}
	c := checker.New(nvd.ModifiedMetadata, nvd.Modified,
		getLastModifiedMetadataMock, putLastModifiedMetadataMock,
		nvd.RecentMetadata, nvd.Recent,
		getLastRecentMetadataMock, putLastRecentMetadataMock,
		isNotifiedMock, putNotifiedMock,
		[]checker.Notifier{console}, checker.IncludeGo, checker.IncludeNodeJS)
	items, err := c.RecentOrUpdated()
	if err != nil {
		return
	}
	logger.For(pkg, "main").WithField("itemCount", len(items)).Info("complete")
	return
}

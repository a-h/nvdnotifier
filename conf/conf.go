package conf

import (
	"errors"
	"os"
	"strings"
)

// FromEnvironment loads the config from the environment.
func FromEnvironment() (c Configuration, err error) {
	c = Configuration{
		DynamoDBRegion:        os.Getenv("DYNAMODB_REGION"),
		MetadataTableName:     os.Getenv("METADATA_TABLE_NAME"),
		NotificationTableName: os.Getenv("NOTIFICATION_TABLE_NAME"),
		SlackWebhookURL:       os.Getenv("SLACK_WEBHOOK_URL"),
		RunLocal:              os.Getenv("RUN_LOCAL") != "",
	}
	var errs []string
	if c.DynamoDBRegion == "" {
		errs = append(errs, "DYNAMODB_REGION must not be empty")
	}
	if c.MetadataTableName == "" {
		errs = append(errs, "METADATA_TABLE_NAME must not be empty")
	}
	if c.NotificationTableName == "" {
		errs = append(errs, "NOTIFICATION_TABLE_NAME must not be empty")
	}
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, ", "))
	}
	return
}

// Configuration is the configuration of the
type Configuration struct {
	DynamoDBRegion        string
	MetadataTableName     string
	NotificationTableName string
	SlackWebhookURL       string
	RunLocal              bool
}

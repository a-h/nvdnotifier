DYNAMODB_REGION=eu-west-2 \
METADATA_TABLE_NAME=nvdnotifier-prod-metadata \
NOTIFICATION_TABLE_NAME=nvdnotifier-prod-notification \
RUN_LOCAL=true \
go run ./check/main.go
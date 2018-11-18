package dynamo

import (
	"github.com/a-h/nvdnotifier/nvd"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

func NewNotificationStore(region, tableName string) (store *NotificationStore, err error) {
	conf := &aws.Config{
		Region: aws.String(region),
	}
	sess, err := session.NewSession(conf)
	if err != nil {
		return
	}
	store = &NotificationStore{
		Client:    dynamodb.New(sess),
		TableName: aws.String(tableName),
	}
	return
}

type NotificationStore struct {
	Client    *dynamodb.DynamoDB
	TableName *string
}

type notificationRecord struct {
	ID string      `json:"id"`
	D  nvd.CVEItem `json:"d"`
}

func (mds NotificationStore) Put(d nvd.CVEItem) (err error) {
	hash, err := d.Hash()
	if err != nil {
		return
	}
	item, err := dynamodbattribute.MarshalMap(notificationRecord{
		ID: hash,
		D:  d,
	})
	if err != nil {
		return
	}
	_, err = mds.Client.PutItem(&dynamodb.PutItemInput{
		TableName: mds.TableName,
		Item:      item,
	})
	return
}

// Get retrieves data from DynamoDB.
func (mds NotificationStore) Get(hash string) (d nvd.CVEItem, ok bool, err error) {
	gio, err := mds.Client.GetItem(&dynamodb.GetItemInput{
		ConsistentRead: aws.Bool(true),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(hash),
			},
		},
		TableName: mds.TableName,
	})
	if err != nil {
		return
	}
	var r notificationRecord
	err = dynamodbattribute.UnmarshalMap(gio.Item, &r)
	ok = r.ID != ""
	d = r.D
	return
}

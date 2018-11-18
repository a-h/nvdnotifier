package dynamo

import (
	"github.com/a-h/nvdnotifier/nvd"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

func NewMetadataStore(region, tableName string) (store *MetadataStore, err error) {
	conf := &aws.Config{
		Region: aws.String(region),
	}
	sess, err := session.NewSession(conf)
	if err != nil {
		return
	}
	store = &MetadataStore{
		Client:    dynamodb.New(sess),
		TableName: aws.String(tableName),
	}
	return
}

type MetadataStore struct {
	Client    *dynamodb.DynamoDB
	TableName *string
}

type metadataRecord struct {
	URL string   `json:"url"`
	M   nvd.Meta `json:"m"`
}

func (mds MetadataStore) Put(url string, m nvd.Meta) (err error) {
	item, err := dynamodbattribute.MarshalMap(metadataRecord{
		URL: url,
		M:   m,
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
func (mds MetadataStore) Get(url string) (m nvd.Meta, ok bool, err error) {
	gio, err := mds.Client.GetItem(&dynamodb.GetItemInput{
		ConsistentRead: aws.Bool(true),
		Key: map[string]*dynamodb.AttributeValue{
			"url": {
				S: aws.String(url),
			},
		},
		TableName: mds.TableName,
	})
	if err != nil {
		return
	}
	var r metadataRecord
	err = dynamodbattribute.UnmarshalMap(gio.Item, &r)
	ok = r.URL != ""
	m = r.M
	return
}

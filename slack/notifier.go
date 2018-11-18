package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func NewMessage(subject, text string) Message {
	return Message{
		Text: subject,
		Attachments: []Attachment{
			Attachment{
				Text:  text,
				Color: "warning",
				Title: "CVE",
			},
		},
	}
}

type Message struct {
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments"`
}

type Attachment struct {
	Text  string `json:"text"`
	Color string `json:"color"`
	Title string `json:"title"`
}

func NewNotifier(webhookURL string) Notifier {
	return Notifier{
		WebhookURL: webhookURL,
	}
}

type Notifier struct {
	WebhookURL string
}

func (n Notifier) Push(m Message) (err error) {
	client := &http.Client{}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", n.WebhookURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("unexpected Slack webhook status code: %v, body: '%v'", resp.StatusCode, string(body))
	}
	return nil
}

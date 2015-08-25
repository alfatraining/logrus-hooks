package graylog

import (
	"strings"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/alfatraining/go-gelf/gelf"
)

const SyslogInfoLevel = 6

type CustomTypeStringer struct {
}

func (c CustomTypeStringer) String() string {
	return "CustomTypeStringer()!"
}

func TestWritingToUDP(t *testing.T) {
	r, err := gelf.NewReader("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewReader: %s", err)
	}
	hook := NewGraylogHook(r.Addr(), "test_facility", map[string]interface{}{"foo": "bar"})
	msgData := "test message\nsecond line"
	ct := &CustomTypeStringer{}

	log := logrus.New()
	log.Hooks.Add(hook)
	log.WithFields(logrus.Fields{"withField": "1", "custom": ct}).Info(msgData)

	msg, err := r.ReadMessage()

	if err != nil {
		t.Errorf("ReadMessage: %s", err)
	}

	if msg.Short != "test message" {
		t.Errorf("msg.Short: expected %s, got %s", msgData, msg.Full)
	}

	if msg.Full != msgData {
		t.Errorf("msg.Full: expected %s, got %s", msgData, msg.Full)
	}

	if msg.Level != SyslogInfoLevel {
		t.Errorf("msg.Level: expected: %d, got %d)", SyslogInfoLevel, msg.Level)
	}

	if msg.Facility != "test_facility" {
		t.Errorf("msg.Facility: expected %#v, got %#v)", "test_facility", msg.Facility)
	}

	fileExpected := "graylog_hook_test.go"
	if !strings.HasSuffix(msg.File, fileExpected) {
		t.Errorf("msg.File: expected %s, got %s", fileExpected,
			msg.File)
	}

	if msg.Line != 31 { // Update this if code is updated above
		t.Errorf("msg.Line: expected %d, got %d", 25, msg.Line)
	}

	const expectedExtraFields = 3
	if len(msg.Extra) != expectedExtraFields {
		t.Errorf("wrong number of extra fields (exp: %d, got %d) in %v", expectedExtraFields, len(msg.Extra), msg.Extra)
	}

	extra := map[string]string{"foo": "bar", "withField": "1", "custom": ct.String()}

	for k, v := range extra {
		// Remember extra fileds are prefixed with "_"
		str, ok := msg.Extra["_"+k].(string)
		if ok == false {
			t.Errorf("Expected string as type of '%s' but it was not", k)
		}
		if str != extra[k] {
			t.Errorf("Expected extra '%s' to be %#v, got %#v", k, v, msg.Extra["_"+k])
		}
	}
}

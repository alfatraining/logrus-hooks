package graylog

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/alfatraining/go-gelf/gelf"
)

// Set graylog.BufSize = <value> _before_ calling NewGraylogHook
// Once the buffer is full, logging will start blocking, waiting for slots to
// be available in the queue.
var BufSize uint = 8192

//
// 0       Emergency: system is unusable
// 1       Alert: action must be taken immediately
// 2       Critical: critical conditions
// 3       Error: error conditions
// 4       Warning: warning conditions
// 5       Notice: normal but significant condition
// 6       Informational: informational messages
// 7       Debug: debug-level messages
var levelMap = map[logrus.Level]int32{logrus.PanicLevel: 1, logrus.FatalLevel: 2, logrus.ErrorLevel: 3, logrus.InfoLevel: 6, logrus.WarnLevel: 4, logrus.DebugLevel: 7}

// Hook to send logs to a logging service compatible with the Graylog API and the GELF format.
type Hook struct {
	Facility   string
	Extra      map[string]interface{}
	gelfLogger *gelf.Writer
	buf        chan graylogEntry
}

// Graylog needs file and line params
type graylogEntry struct {
	*logrus.Entry
	file string
	line int
}

// NewGraylogHook creates a hook to be added to an instance of logger.
func NewGraylogHook(addr string, facility string, extra map[string]interface{}) *Hook {
	g, err := gelf.NewWriter(addr)
	if err != nil {
		logrus.WithField("err", err).Info("Can't create Gelf logger")
		return nil
	}
	hook := &Hook{
		Facility:   facility,
		Extra:      extra,
		gelfLogger: g,
		buf:        make(chan graylogEntry, BufSize),
	}
	go hook.fire() // Log in background
	return hook
}

// Fire is called when a log event is fired.
// We assume the entry will be altered by another hook,
// otherwise we might logging something wrong to Graylog
func (hook *Hook) Fire(entry *logrus.Entry) error {
	// get caller file and line here, it won't be available inside the goroutine
	// 1 for the function that called us.
	file, line := getCallerIgnoringLogMulti(1)
	hook.buf <- graylogEntry{entry, file, line}
	return nil
}

// [ks] - format based on type
func formatForJSON(value interface{}) interface{} {
	switch value.(type) {
	case int:
		return value
	case float64:
		return value
	case bool:
		return value
	case string:
		return value
	default:
		return fmt.Sprintf("%s", value)
	}
}

// fire will loop on the 'buf' channel, and write entries to graylog
func (hook *Hook) fire() {
	for {
		entry := <-hook.buf // receive new entry on channel
		host, err := os.Hostname()
		if err != nil {
			host = "localhost"
		}

		w := hook.gelfLogger

		// remove trailing and leading whitespace
		p := bytes.TrimSpace([]byte(entry.Message))

		// If there are newlines in the message, use the first line
		// for the short message and set the full message to the
		// original input.  If the input has no newlines, stick the
		// whole thing in Short.
		short := p
		full := []byte("")
		if i := bytes.IndexRune(p, '\n'); i > 0 {
			short = p[:i]
			full = p
		}

		// map logrus to syslog levels
		level, ok := levelMap[entry.Level]
		if ok == false {
			level = levelMap[logrus.InfoLevel]
		}

		extra := map[string]interface{}{}

		// add the logrus Level as a field in order to have the name of the level as well... I can't watch levels as numbers anymore
		extra["_severity"] = fmt.Sprintf("%s", entry.Level)

		// Merge extra fields
		for k, v := range hook.Extra {
			k = fmt.Sprintf("_%s", k) // "[...] every field you send and prefix with a _ (underscore) will be treated as an additional field."
			extra[k] = formatForJSON(v)
		}

		// Don't modify entry.Data directly, as the entry will used after this hook was fired
		for k, v := range entry.Data {
			k = fmt.Sprintf("_%s", k) // "[...] every field you send and prefix with a _ (underscore) will be treated as an additional field."
			extra[k] = formatForJSON(v)
		}

		m := gelf.Message{
			Version:    "1.1",
			Host:       host,
			Short:      string(short),
			Full:       string(full),
			TimeUnixMs: time.Now().UnixNano() / 1000000,
			Level:      level,
			Facility:   hook.Facility,
			File:       entry.file,
			Line:       entry.line,
			Extra:      extra,
		}

		w.WriteMessage(&m) // If WriteMessage failed, just give up, don't look to death
	}
}

// Levels returns the available logging levels. Required by logrus hook interface
func (hook *Hook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

// getCaller returns the filename and the line info of a function
// further down in the call stack.  Passing 0 in as callDepth would
// return info on the function calling getCallerIgnoringLog, 1 the
// parent function, and so on.  Any suffixes passed to getCaller are
// path fragments like "/pkg/log/log.go", and functions in the call
// stack from that file are ignored.
func getCaller(callDepth int, suffixesToIgnore ...string) (file string, line int) {
	// bump by 1 to ignore the getCaller (this) stackframe
	callDepth++
outer:
	for {
		var ok bool
		_, file, line, ok = runtime.Caller(callDepth)
		if !ok {
			file = "???"
			line = 0
			break
		}

		for _, s := range suffixesToIgnore {
			if strings.HasSuffix(file, s) {
				callDepth++
				continue outer
			}
		}
		break
	}
	return
}

func getCallerIgnoringLogMulti(callDepth int) (string, int) {
	// the +1 is to ignore this (getCallerIgnoringLogMulti) frame
	return getCaller(callDepth+1, "logrus/hooks.go", "logrus/entry.go", "logrus/logger.go", "logrus/exported.go", "asm_amd64.s")
}

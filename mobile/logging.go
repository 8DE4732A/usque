package mobile

import (
	"bytes"
	"fmt"
	"log"
)

// Logger is a gomobile-compatible interface for receiving log messages from the native library.
type Logger interface {
	Log(msg string)
}

var globalLogger Logger

// SetLogger sets the global logger and redirects the Go standard log package output to it.
// Should be called once during app initialization.
func SetLogger(l Logger) {
	globalLogger = l
	if l != nil {
		log.SetOutput(&logWriter{})
		log.SetFlags(0)
	}
}

// logWriter implements io.Writer, forwarding Go log output to globalLogger.
type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	msg := string(bytes.TrimRight(p, "\n"))
	if globalLogger != nil {
		globalLogger.Log(msg)
	}
	return len(p), nil
}

func logf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Log(fmt.Sprintf(format, args...))
	}
}

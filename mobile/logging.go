package mobile

import "fmt"

// Logger is a gomobile-compatible interface for receiving log messages from the native library.
type Logger interface {
	Log(msg string)
}

var globalLogger Logger

// SetLogger sets the global logger. Should be called once during app initialization.
func SetLogger(l Logger) {
	globalLogger = l
}

func logf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Log(fmt.Sprintf(format, args...))
	}
}

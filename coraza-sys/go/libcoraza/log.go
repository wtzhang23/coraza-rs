package main

/*
#include <stdlib.h>

typedef enum coraza_log_level_t {
	CORAZA_LOG_LEVEL_TRACE,
	CORAZA_LOG_LEVEL_DEBUG,
	CORAZA_LOG_LEVEL_INFO,
	CORAZA_LOG_LEVEL_WARN,
	CORAZA_LOG_LEVEL_ERROR,
} coraza_log_level_t;

typedef void (*coraza_log_cb) (void *, coraza_log_level_t, const char *msg, const char *fields);
static void call_log_cb(coraza_log_cb cb, void *ctx, coraza_log_level_t level, const char *msg, const char *fields) {
	cb(ctx, level, msg, fields);
}
*/
import "C"
import (
	"io"
	"log"
	"unsafe"

	"github.com/corazawaf/coraza/v3/debuglog"
)

var _ debuglog.Logger = logger{}

type logger struct {
	debuglog.Logger
	writer io.Writer
}

var _ debuglog.Logger = logger{}

func newLogger(ctx *C.void, cb C.coraza_log_cb) debuglog.Logger {
	logger := logger{
		writer: nil,
	}
	logger.Logger = debuglog.DefaultWithPrinterFactory(func(w io.Writer) debuglog.Printer {
		if logger.writer != nil {
			return func(lvl debuglog.Level, message, fields string) {
				log.New(logger.writer, "", log.LstdFlags).Printf("[%s] %s %s", lvl.String(), message, fields)
			}
		}
		return func(lvl debuglog.Level, message, fields string) {
			rawLevel := C.CORAZA_LOG_LEVEL_DEBUG
			switch lvl {
			case debuglog.LevelTrace:
				rawLevel = C.CORAZA_LOG_LEVEL_TRACE
			case debuglog.LevelDebug:
				rawLevel = C.CORAZA_LOG_LEVEL_DEBUG
			case debuglog.LevelInfo:
				rawLevel = C.CORAZA_LOG_LEVEL_INFO
			case debuglog.LevelWarn:
				rawLevel = C.CORAZA_LOG_LEVEL_WARN
			case debuglog.LevelError:
				rawLevel = C.CORAZA_LOG_LEVEL_ERROR
			}
			cMsg := C.CString(message)
			cFields := C.CString(fields)
			defer C.free(unsafe.Pointer(cMsg))
			defer C.free(unsafe.Pointer(cFields))
			C.call_log_cb(cb, unsafe.Pointer(ctx), C.coraza_log_level_t(rawLevel), cMsg, cFields)
		}
	})
	return logger
}

func (l logger) WithLevel(lvl debuglog.Level) debuglog.Logger {
	return logger{
		Logger: l.Logger.WithLevel(lvl),
	}
}

func (l logger) WithOutput(w io.Writer) debuglog.Logger {
	return logger{
		Logger: l,
		writer: w,
	}
}

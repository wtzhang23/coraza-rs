// Copied mostly from https://github.com/corazawaf/libcoraza
package main

/*
#ifndef _LIBCORAZA_H_
#define _LIBCORAZA_H_
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

typedef struct coraza_intervention_t
{
	char *action;
	size_t action_len;
    int status;
} coraza_intervention_t;

typedef struct coraza_error_t
{
	char *msg;
	size_t msg_len;
} coraza_error_t;

typedef uintptr_t coraza_waf_config_t;
typedef uintptr_t coraza_waf_t;
typedef uintptr_t coraza_transaction_t;

typedef enum coraza_log_level_t {
	CORAZA_LOG_LEVEL_TRACE,
	CORAZA_LOG_LEVEL_DEBUG,
	CORAZA_LOG_LEVEL_INFO,
	CORAZA_LOG_LEVEL_WARN,
	CORAZA_LOG_LEVEL_ERROR,
} coraza_log_level_t;

typedef void (*coraza_log_cb) (void *, coraza_log_level_t, const char *msg, const char *fields);

typedef enum coraza_severity_t {
	CORAZA_SEVERITY_DEBUG,
	CORAZA_SEVERITY_INFO,
	CORAZA_SEVERITY_NOTICE,
	CORAZA_SEVERITY_WARNING,
	CORAZA_SEVERITY_ERROR,
	CORAZA_SEVERITY_CRITICAL,
	CORAZA_SEVERITY_ALERT,
	CORAZA_SEVERITY_EMERGENCY,
} coraza_severity_t;

typedef void (*coraza_error_cb) (void *, coraza_severity_t, const char *msg);

static void call_error_cb(coraza_error_cb cb, void *ctx, coraza_severity_t severity, const char *msg) {
	cb(ctx, severity, msg);
}
#endif
*/
import "C"
import (
	"io"
	"os"
	"runtime/cgo"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type WafConfigHandle struct {
	config coraza.WAFConfig
}

type WafHandle struct {
	waf coraza.WAF
}

type TransactionHandle struct {
	tx types.Transaction
}

//export coraza_new_waf_config
func coraza_new_waf_config() C.coraza_waf_config_t {
	config := coraza.NewWAFConfig().WithRootFS(rootFS)
	handle := &WafConfigHandle{
		config: config,
	}
	return C.coraza_waf_config_t(cgo.NewHandle(handle))
}

//export coraza_add_rules_to_waf_config
func coraza_add_rules_to_waf_config(c C.coraza_waf_config_t, rules *C.char, rules_len C.size_t) {
	handle := cgo.Handle(c).Value().(*WafConfigHandle)
	handle.config = handle.config.WithDirectives(C.GoStringN(rules, C.int(rules_len)))
}

//export coraza_add_rules_from_file_to_waf_config
func coraza_add_rules_from_file_to_waf_config(c C.coraza_waf_config_t, file *C.char, file_len C.size_t) {
	handle := cgo.Handle(c).Value().(*WafConfigHandle)
	handle.config = handle.config.WithDirectivesFromFile(C.GoStringN(file, C.int(file_len)))
}

//export coraza_add_log_callback_to_waf_config
func coraza_add_log_callback_to_waf_config(c C.coraza_waf_config_t, cb C.coraza_log_cb, userData *C.void) {
	handle := cgo.Handle(c).Value().(*WafConfigHandle)
	handle.config = handle.config.WithDebugLogger(newLogger(userData, cb))
}

//export coraza_add_error_callback_to_waf_config
func coraza_add_error_callback_to_waf_config(c C.coraza_waf_config_t, cb C.coraza_error_cb, userData *C.void) {
	handle := cgo.Handle(c).Value().(*WafConfigHandle)
	handle.config = handle.config.WithErrorCallback(func(rule types.MatchedRule) {
		severity := C.CORAZA_SEVERITY_DEBUG
		switch rule.Rule().Severity() {
		case types.RuleSeverityEmergency:
			severity = C.CORAZA_SEVERITY_EMERGENCY
		case types.RuleSeverityAlert:
			severity = C.CORAZA_SEVERITY_ALERT
		case types.RuleSeverityCritical:
			severity = C.CORAZA_SEVERITY_CRITICAL
		case types.RuleSeverityError:
			severity = C.CORAZA_SEVERITY_ERROR
		case types.RuleSeverityWarning:
			severity = C.CORAZA_SEVERITY_WARNING
		case types.RuleSeverityNotice:
			severity = C.CORAZA_SEVERITY_NOTICE
		case types.RuleSeverityInfo:
			severity = C.CORAZA_SEVERITY_INFO
		case types.RuleSeverityDebug:
			severity = C.CORAZA_SEVERITY_DEBUG
		}
		cMsg := C.CString(rule.ErrorLog())
		defer C.free(unsafe.Pointer(cMsg))
		C.call_error_cb(cb, unsafe.Pointer(userData), C.coraza_severity_t(severity), cMsg)
	})
}

//export coraza_free_waf_config
func coraza_free_waf_config(c C.coraza_waf_config_t) C.int {
	cgo.Handle(c).Delete()
	return 0
}

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf(c C.coraza_waf_config_t, er *C.coraza_error_t) C.coraza_waf_t {
	wafConfigHandle := cgo.Handle(c).Value().(*WafConfigHandle)
	waf, err := coraza.NewWAF(wafConfigHandle.config)
	if err != nil {
		errMsg := err.Error()
		*er = C.coraza_error_t{
			msg:     C.CString(errMsg),
			msg_len: C.size_t(len(errMsg)),
		}
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	handle := &WafHandle{
		waf: waf,
	}
	return C.coraza_waf_t(cgo.NewHandle(handle))
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t) C.coraza_transaction_t {
	handle := cgo.Handle(waf).Value().(*WafHandle)
	tx := handle.waf.NewTransaction()
	if tx == nil {
		return 0
	}
	return C.coraza_transaction_t(cgo.NewHandle(&TransactionHandle{tx: tx}))
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, id *C.char, id_len C.size_t) C.coraza_transaction_t {
	handle := cgo.Handle(waf).Value().(*WafHandle)
	tx := handle.waf.NewTransactionWithID(C.GoStringN(id, C.int(id_len)))
	if tx == nil {
		return 0
	}
	return C.coraza_transaction_t(cgo.NewHandle(&TransactionHandle{tx: tx}))
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t) *C.coraza_intervention_t {
	handle := cgo.Handle(tx).Value().(*TransactionHandle)
	if handle.tx.Interruption() == nil {
		return nil
	}
	action := handle.tx.Interruption().Action
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(action)
	mem.action_len = C.size_t(len(action))
	mem.status = C.int(handle.tx.Interruption().Status)
	return mem
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, sourceAddress_len C.size_t, clientPort C.int, serverHost *C.char, serverHost_len C.size_t, serverPort C.int) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	srcAddr := C.GoStringN(sourceAddress, C.int(sourceAddress_len))
	cp := int(clientPort)
	ch := C.GoStringN(serverHost, C.int(serverHost_len))
	sp := int(serverPort)
	handle.tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	if _, err := handle.tx.ProcessRequestBody(); err != nil {
		return 1
	}
	return 0
}

// msr->t, r->unparsed_uri, r->method, r->protocol + offset
//
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, uri_len C.size_t, method *C.char, method_len C.size_t, proto *C.char, proto_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.ProcessURI(C.GoStringN(uri, C.int(uri_len)), C.GoStringN(method, C.int(method_len)), C.GoStringN(proto, C.int(proto_len)))
	return 0
}

//export coraza_set_server_name
func coraza_set_server_name(t C.coraza_transaction_t, server_name *C.char, server_name_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.SetServerName(C.GoStringN(server_name, C.int(server_name_len)))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, name_len C.size_t, value *C.char, value_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.AddRequestHeader(C.GoStringN(name, C.int(name_len)), C.GoStringN(value, C.int(value_len)))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.ProcessLogging()
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	if _, _, err := handle.tx.WriteRequestBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_add_get_args
func coraza_add_get_args(t C.coraza_transaction_t, name *C.char, name_len C.size_t, value *C.char, value_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.AddGetRequestArgument(C.GoStringN(name, C.int(name_len)), C.GoStringN(value, C.int(value_len)))
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, name_len C.size_t, value *C.char, value_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.AddResponseHeader(C.GoStringN(name, C.int(name_len)), C.GoStringN(value, C.int(value_len)))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	if _, _, err := handle.tx.WriteResponseBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	if _, err := handle.tx.ProcessResponseBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char, proto_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	handle.tx.ProcessResponseHeaders(int(status), C.GoStringN(proto, C.int(proto_len)))
	return 0
}

//export coraza_free_transaction
func coraza_free_transaction(t C.coraza_transaction_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	if handle.tx.Close() != nil {
		return 1
	}
	cgo.Handle(t).Delete()
	return 0
}

//export coraza_free_intervention
func coraza_free_intervention(it *C.coraza_intervention_t) C.int {
	if it == nil {
		return 1
	}
	defer C.free(unsafe.Pointer(it))
	C.free(unsafe.Pointer(it.action))
	return 0
}

//export coraza_rules_merge
func coraza_rules_merge(w1 C.coraza_waf_t, w2 C.coraza_waf_t, er **C.char) C.int {
	return 0
}

//export coraza_request_body_from_file
func coraza_request_body_from_file(t C.coraza_transaction_t, file *C.char, file_len C.size_t) C.int {
	handle := cgo.Handle(t).Value().(*TransactionHandle)
	f, err := os.Open(C.GoStringN(file, C.int(file_len)))
	if err != nil {
		return 1
	}
	defer f.Close()
	// we read the file in chunks and send it to the engine
	for {
		buf := make([]byte, 1024)
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 1
		}
		if _, _, err := handle.tx.WriteRequestBody(buf[:n]); err != nil {
			return 1
		}
	}
	return 0
}

//export coraza_free_waf
func coraza_free_waf(t C.coraza_waf_t) C.int {
	cgo.Handle(t).Delete()
	return 0
}

//export coraza_free_error
func coraza_free_error(e C.coraza_error_t) C.int {
	if e.msg != nil {
		C.free(unsafe.Pointer(e.msg))
	}
	return 0
}

//export coraza_set_log_cb
func coraza_set_log_cb(waf C.coraza_waf_t, cb C.coraza_log_cb) {
}

/*
Internal helpers
*/

// It should just be C.CString(s) but we need this to build tests
func stringToC(s string) (*C.char, C.size_t) {
	return C.CString(s), C.size_t(len(s))
}

func nilWafError() C.coraza_error_t {
	return C.coraza_error_t{
		msg:     nil,
		msg_len: 0,
	}
}

func main() {}

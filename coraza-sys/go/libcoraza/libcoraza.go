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
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

var configMap = sync.Map{}
var wafMap = sync.Map{}
var txMap = sync.Map{}
var txHandleCounter uint64 // Atomic counter for transaction handles

type WafConfigHandle struct {
	config coraza.WAFConfig
}

type WafHandle struct {
	waf coraza.WAF
}

//export coraza_new_waf_config
func coraza_new_waf_config() C.coraza_waf_config_t {
	config := coraza.NewWAFConfig().WithRootFS(rootFS)
	handle := &WafConfigHandle{
		config: config,
	}
	return configMapInsert(handle)
}

//export coraza_add_rules_to_waf_config
func coraza_add_rules_to_waf_config(c C.coraza_waf_config_t, rules *C.char, rules_len C.size_t) {
	handle := ptrToWafConfigHandle(c)
	handle.config = handle.config.WithDirectives(C.GoStringN(rules, C.int(rules_len)))
}

//export coraza_add_rules_from_file_to_waf_config
func coraza_add_rules_from_file_to_waf_config(c C.coraza_waf_config_t, file *C.char, file_len C.size_t) {
	handle := ptrToWafConfigHandle(c)
	handle.config = handle.config.WithDirectivesFromFile(C.GoStringN(file, C.int(file_len)))
}

//export coraza_add_log_callback_to_waf_config
func coraza_add_log_callback_to_waf_config(c C.coraza_waf_config_t, cb C.coraza_log_cb, userData *C.void) {
	handle := ptrToWafConfigHandle(c)
	handle.config = handle.config.WithDebugLogger(newLogger(userData, cb))
}

//export coraza_add_error_callback_to_waf_config
func coraza_add_error_callback_to_waf_config(c C.coraza_waf_config_t, cb C.coraza_error_cb, userData *C.void) {
	handle := ptrToWafConfigHandle(c)
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
		C.call_error_cb(cb, unsafe.Pointer(userData), C.coraza_severity_t(severity), C.CString(rule.Message()))
	})
}

//export coraza_free_waf_config
func coraza_free_waf_config(c C.coraza_waf_config_t) C.int {
	configMapDelete(c)
	return 0
}

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf(c C.coraza_waf_config_t, er *C.coraza_error_t) C.coraza_waf_t {
	wafConfigHandle := ptrToWafConfigHandle(c)
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
	return wafMapInsert(handle)
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t) C.coraza_transaction_t {
	handle := ptrToWafHandle(waf)
	tx := handle.waf.NewTransaction()
	return txMapInsert(tx)
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, id *C.char, id_len C.size_t) C.coraza_transaction_t {
	handle := ptrToWafHandle(waf)
	tx := handle.waf.NewTransactionWithID(C.GoStringN(id, C.int(id_len)))
	return txMapInsert(tx)
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t) *C.coraza_intervention_t {
	t := ptrToTransactionHandle(tx)
	if t.Interruption() == nil {
		return nil
	}
	action := t.Interruption().Action
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(action)
	mem.action_len = C.size_t(len(action))
	mem.status = C.int(t.Interruption().Status)
	return mem
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, sourceAddress_len C.size_t, clientPort C.int, serverHost *C.char, serverHost_len C.size_t, serverPort C.int) C.int {
	tx := ptrToTransactionHandle(t)
	srcAddr := C.GoStringN(sourceAddress, C.int(sourceAddress_len))
	cp := int(clientPort)
	ch := C.GoStringN(serverHost, C.int(serverHost_len))
	sp := int(serverPort)
	tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransactionHandle(t)
	if _, err := tx.ProcessRequestBody(); err != nil {
		return 1
	}
	return 0
}

// msr->t, r->unparsed_uri, r->method, r->protocol + offset
//
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, uri_len C.size_t, method *C.char, method_len C.size_t, proto *C.char, proto_len C.size_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.ProcessURI(C.GoStringN(uri, C.int(uri_len)), C.GoStringN(method, C.int(method_len)), C.GoStringN(proto, C.int(proto_len)))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, name_len C.size_t, value *C.char, value_len C.size_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.AddRequestHeader(C.GoStringN(name, C.int(name_len)), C.GoStringN(value, C.int(value_len)))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.ProcessLogging()
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransactionHandle(t)
	if _, _, err := tx.WriteRequestBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_add_get_args
func coraza_add_get_args(t C.coraza_transaction_t, name *C.char, name_len C.size_t, value *C.char, value_len C.size_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.AddGetRequestArgument(C.GoStringN(name, C.int(name_len)), C.GoStringN(value, C.int(value_len)))
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, name_len C.size_t, value *C.char, value_len C.size_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.AddResponseHeader(C.GoStringN(name, C.int(name_len)), C.GoStringN(value, C.int(value_len)))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransactionHandle(t)
	if _, _, err := tx.WriteResponseBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransactionHandle(t)
	if _, err := tx.ProcessResponseBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char, proto_len C.size_t) C.int {
	tx := ptrToTransactionHandle(t)
	tx.ProcessResponseHeaders(int(status), C.GoStringN(proto, C.int(proto_len)))
	return 0
}

//export coraza_free_transaction
func coraza_free_transaction(t C.coraza_transaction_t) C.int {
	tx := ptrToTransactionHandle(t)
	if tx.Close() != nil {
		return 1
	}
	txMapDelete(t)
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
	tx := ptrToTransactionHandle(t)
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
		if _, _, err := tx.WriteRequestBody(buf[:n]); err != nil {
			return 1
		}
	}
	return 0
}

//export coraza_free_waf
func coraza_free_waf(t C.coraza_waf_t) C.int {
	wafMapDelete(t)
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

func configMapInsert(handle *WafConfigHandle) C.coraza_waf_config_t {
	ptr := wafConfigHandleToPtr(handle)
	configMap.Store(ptr, handle)
	return C.coraza_waf_config_t(ptr)
}

func configMapDelete(config C.coraza_waf_config_t) {
	ptr := uintptr(config)
	configMap.Delete(ptr)
}

func wafMapInsert(handle *WafHandle) C.coraza_waf_t {
	ptr := wafToPtr(handle)
	wafMap.Store(ptr, handle)
	return C.coraza_waf_t(ptr)
}

func wafMapDelete(waf C.coraza_waf_t) {
	ptr := uintptr(waf)
	wafMap.Delete(ptr)
}

func txMapInsert(tx types.Transaction) C.coraza_transaction_t {
	// Use atomic counter to generate unique handle IDs
	// Start from 1 to ensure 0 is invalid
	handle := atomic.AddUint64(&txHandleCounter, 1)
	if handle == 0 {
		// Wrap around (extremely unlikely, but handle it)
		handle = atomic.AddUint64(&txHandleCounter, 1)
	}
	txMap.Store(handle, tx)
	return C.coraza_transaction_t(handle)
}

func txMapDelete(tx C.coraza_transaction_t) {
	handle := uintptr(tx)
	txMap.Delete(handle)
}

func ptrToWafConfigHandle(config C.coraza_waf_config_t) *WafConfigHandle {
	ptr := uintptr(config)
	handle, ok := configMap.Load(ptr)
	if !ok {
		return nil
	}
	return handle.(*WafConfigHandle)
}

func ptrToWafHandle(waf C.coraza_waf_t) *WafHandle {
	ptr := uintptr(waf)
	handle, ok := wafMap.Load(ptr)
	if !ok {
		return nil
	}
	return handle.(*WafHandle)
}

func ptrToTransactionHandle(t C.coraza_transaction_t) types.Transaction {
	handle := uintptr(t)
	tx, ok := txMap.Load(handle)
	if !ok {
		return nil
	}
	return tx.(types.Transaction)
}

// transactionToPtr is no longer used with handle-based system
// Kept for backward compatibility but not called
func transactionToPtr(tx types.Transaction) uintptr {
	return reflect.ValueOf(&tx).Pointer()
}

func wafToPtr(waf *WafHandle) uintptr {
	return reflect.ValueOf(&waf).Pointer()
}

func wafConfigHandleToPtr(config *WafConfigHandle) uintptr {
	return reflect.ValueOf(&config).Pointer()
}

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

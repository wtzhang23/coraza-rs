package main

/*
#include <stdint.h>
*/
import "C"
import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var waf *coraza.WAF
var wafPtr uint64

func TestWafInitialization(t *testing.T) {
	config := coraza_new_waf_config()
	err := nilWafError()
	waf2 := coraza_new_waf(config, &err)
	wafPtr = uint64(waf2)
}

func TestWafIsConsistent(t *testing.T) {
	if waf == nil {
		TestWafInitialization(t)
	}
}

func TestAddRulesToWaf(t *testing.T) {
}

func TestCoraza_add_get_args(t *testing.T) {
	config := coraza_new_waf_config()
	err := nilWafError()
	waf := coraza_new_waf(config, &err)
	tt := coraza_new_transaction(waf)
	aa, aa_len := stringToC("aa")
	bb, bb_len := stringToC("bb")
	coraza_add_get_args(tt, aa, aa_len, bb, bb_len)
	tx := ptrToTransaction(tt)
	txi := tx.(plugintypes.TransactionState)
	argsGet := txi.Variables().ArgsGet()
	value := argsGet.Get("aa")
	if len(value) != 1 && value[0] != "bb" {
		t.Fatal("coraza_add_get_args can't add args")
	}
	dd, dd_len := stringToC("dd")
	ee, ee_len := stringToC("ee")
	coraza_add_get_args(tt, dd, dd_len, ee, ee_len)
	value = argsGet.Get("dd")
	if len(value) != 1 && value[0] != "ee" {
		t.Fatal("coraza_add_get_args can't add args with another key")
	}
	aa, aa_len = stringToC("aa")
	cc, cc_len := stringToC("cc")
	coraza_add_get_args(tt, aa, aa_len, cc, cc_len)
	value = argsGet.Get("aa")
	if len(value) != 2 && value[0] != "bb" && value[1] != "cc" {
		t.Fatal("coraza_add_get_args can't add args with same key more than once")
	}
}

func TestTransactionInitialization(t *testing.T) {
	config := coraza_new_waf_config()
	err := nilWafError()
	waf := coraza_new_waf(config, &err)
	tt := coraza_new_transaction(waf)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
	}
	t2 := coraza_new_transaction(waf)
	if t2 == tt {
		t.Fatal("Transactions are duplicated")
	}
	tx := ptrToTransaction(tt)
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
}

func TestTxCleaning(t *testing.T) {
	config := coraza_new_waf_config()
	err := nilWafError()
	waf := coraza_new_waf(config, &err)
	txPtr := coraza_new_transaction(waf)
	coraza_free_transaction(txPtr)
	if tx := ptrToTransaction(txPtr); tx != nil {
		t.Fatal("Transaction was not removed from the map")
	}
}

func BenchmarkTransactionCreation(b *testing.B) {
	config := coraza_new_waf_config()
	err := nilWafError()
	waf := coraza_new_waf(config, &err)
	for i := 0; i < b.N; i++ {
		coraza_new_transaction(waf)
	}
}

func BenchmarkTransactionProcessing(b *testing.B) {
	config := coraza_new_waf_config()
	rules := `SecRule UNIQUE_ID "" "id:1"`
	rules_ptr, rules_len := stringToC(rules)
	coraza_add_rules_to_waf_config(config, rules_ptr, rules_len)
	err := nilWafError()
	waf := coraza_new_waf(config, &err)
	for i := 0; i < b.N; i++ {
		txPtr := coraza_new_transaction(waf)
		tx := ptrToTransaction(txPtr)
		tx.ProcessConnection("127.0.0.1", 55555, "127.0.0.1", 80)
		tx.ProcessURI("https://www.example.com/some?params=123", "GET", "HTTP/1.1")
		tx.AddRequestHeader("Host", "www.example.com")
		tx.ProcessRequestHeaders()
		_, err := tx.ProcessRequestBody()
		if err != nil {
			b.Fatal("ProcessRequestBody failed: ", err)
		}
		tx.AddResponseHeader("Content-Type", "text/html")
		tx.ProcessResponseHeaders(200, "OK")
		_, err = tx.ProcessResponseBody()
		if err != nil {
			b.Fatal("ProcessResponseBody failed: ", err)
		}
		tx.ProcessLogging()
		tx.Close()
	}
}

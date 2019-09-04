package main

// #cgo darwin CFLAGS: -I ../include -D LD_LIBRARY_PATH=../target/release 
// #cgo darwin LDFLAGS: -L ../target/release/ -lbolt
// #include <libbolt.h>
import "C"
import (
	"encoding/json"
	"strings"
)

type setupResp struct {
	ChannelState  string `json:"channel_state"`
	ChannelToken  string `json:"channel_token"`
	CustState     string `json:"cust_state"`
	MerchState    string `json:"merch_state"`
	Com           string `json:"com"`
	ComProof      string `json:"com_proof"`
	IsTokenValid  bool   `json:"is_token_valid,string"`
	IsEstablished bool   `json:"is_established,string"`
	Payment       string `json:"payment"`
	CloseToken    string `json:"close_token"`
	RevokeToken   string `json:"revoke_token"`
	PayToken      string `json:"pay_token"`
}

func BidirectionalChannelSetup(name string, channelSupport bool) string {
	resp := C.GoString(C.ffishim_bidirectional_channel_setup(C.CString(name), C.uint(btoi(channelSupport))))
	r := processCResponse(resp)
	return r.ChannelState
}

func BidirectionalInitMerchant(channelState string, balanceMerchant int, nameMerchant string) (string, string) {
	resp := C.GoString(C.ffishim_bidirectional_init_merchant(C.CString(channelState), C.int(balanceMerchant), C.CString(nameMerchant)))
	r := processCResponse(resp)
	return r.ChannelToken, r.MerchState
}

func BidirectionalInitCustomer(channelState string, channelToken string, balanceCustomer int, balanceMerchant int, nameCustomer string) (string, string) {
	resp := C.GoString(C.ffishim_bidirectional_init_customer(C.CString(channelState), C.CString(channelToken), C.int(balanceCustomer), C.int(balanceMerchant), C.CString(nameCustomer)))
	r := processCResponse(resp)
	return r.ChannelToken, r.CustState
}

func BidirectionalEstablishCustomerGenerateProof(serChannelToken string, serCustomerWallet string) (string, string, string, string) {
	resp := C.GoString(C.ffishim_bidirectional_establish_customer_generate_proof(C.CString(serChannelToken), C.CString(serCustomerWallet)))
	r := processCResponse(resp)
	return r.ChannelToken, r.CustState, r.Com, r.ComProof
}

func BidirectionalEstablishMerchantIssueCloseToken(serChannelState string, serCom string, serComProof string, initCustBal int, initMerchBal int, serMerchState string) string {
	resp := C.GoString(C.ffishim_bidirectional_establish_merchant_issue_close_token(C.CString(serChannelState), C.CString(serCom), C.CString(serComProof), C.int(initCustBal), C.int(initMerchBal), C.CString(serMerchState)))
	r := processCResponse(resp)
	return r.CloseToken
}

func BidirectionalEstablishMerchantIssuePayToken(serChannelState string, serCom string, serMerchState string) string {
	resp := C.GoString(C.ffishim_bidirectional_establish_merchant_issue_pay_token(C.CString(serChannelState), C.CString(serCom), C.CString(serMerchState)))
	r := processCResponse(resp)
	return r.PayToken
}

func BidirectionalVerifyCloseToken(serChannelState string, serCustomerWallet string, serCloseToken string) (bool, string, string) {
	resp := C.GoString(C.ffishim_bidirectional_verify_close_token(C.CString(serChannelState), C.CString(serCustomerWallet), C.CString(serCloseToken)))
	r := processCResponse(resp)
	return r.IsTokenValid, r.ChannelState, r.CustState
}

func BidirectionalEstablishCustomerFinal(serChannelState string, serCustomerWallet string, serPayToken string) (bool, string, string) {
	resp := C.GoString(C.ffishim_bidirectional_establish_customer_final(C.CString(serChannelState), C.CString(serCustomerWallet), C.CString(serPayToken)))
	r := processCResponse(resp)
	return r.IsEstablished, r.ChannelState, r.CustState
}

func processCResponse(resp string) *setupResp {
	resp = cleanJson(resp)
	r := &setupResp{}
	json.Unmarshal([]byte(resp), r)
	return r
}

func cleanJson(in string) string {
	resp := strings.ReplaceAll(in, "\"", "\\\"")
	resp = strings.ReplaceAll(resp, "'", "\"")
	return resp
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

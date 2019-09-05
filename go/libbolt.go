package main

// #cgo CFLAGS: -I ../include -D LD_LIBRARY_PATH=../target/release
// #cgo LDFLAGS: -L ../target/release/ -lbolt
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
	IsPayValid    bool   `json:"is_pay_valid,string"`
	Payment       string `json:"payment"`
	CloseToken    string `json:"close_token"`
	RevokeToken   string `json:"revoke_token"`
	PayToken      string `json:"pay_token"`
	CustClose     string `json:"cust_close"`
	MerchClose    string `json:"merch_close"`
	Wpk           string `json:"wpk"`
	Error         string `json:"error"`
	Result        string `json:"result"`
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

func BidirectionalPayGeneratePaymentProof(serChannelState string, serCustomerWallet string, amount int) (string, string) {
	resp := C.GoString(C.ffishim_bidirectional_pay_generate_payment_proof(C.CString(serChannelState), C.CString(serCustomerWallet), C.int(amount)))
	r := processCResponse(resp)
	return r.Payment, r.CustState
}

func BidirectionalPayVerifyPaymentProof(serChannelState string, serPayProof string, serMerchState string) (string, string) {
	resp := C.GoString(C.ffishim_bidirectional_pay_verify_payment_proof(C.CString(serChannelState), C.CString(serPayProof), C.CString(serMerchState)))
	r := processCResponse(resp)
	return r.CloseToken, r.MerchState
}

func BidirectionalPayGenerateRevokeToken(serChannelState string, serCustState string, serNewCustState string, serCloseToken string) (string, string) {
	resp := C.GoString(C.ffishim_bidirectional_pay_generate_revoke_token(C.CString(serChannelState), C.CString(serCustState), C.CString(serNewCustState), C.CString(serCloseToken)))
	r := processCResponse(resp)
	return r.RevokeToken, r.CustState
}

func BidirectionalPayVerifyRevokeToken(serRevokeToken string, serMerchState string) (string, string) {
	resp := C.GoString(C.ffishim_bidirectional_pay_verify_revoke_token(C.CString(serRevokeToken), C.CString(serMerchState)))
	r := processCResponse(resp)
	return r.PayToken, r.MerchState
}

func BidirectionalPayVerifyPaymentToken(serChannelState string, serCustState string, serPayToken string) (string, bool) {
	resp := C.GoString(C.ffishim_bidirectional_pay_verify_payment_token(C.CString(serChannelState), C.CString(serCustState), C.CString(serPayToken)))
	r := processCResponse(resp)
	return r.CustState, r.IsPayValid
}

func BidirectionalCustomerClose(serChannelState string, serCustState string) string {
	resp := C.GoString(C.ffishim_bidirectional_customer_close(C.CString(serChannelState), C.CString(serCustState)))
	r := processCResponse(resp)
	return r.CustClose
}

func BidirectionalMerchantClose(serChannelState string, serChannelToken string, serAddress string, serCustClose string, serMerchState string) (string, string, string) {
	resp := C.GoString(C.ffishim_bidirectional_merchant_close(C.CString(serChannelState), C.CString(serChannelToken), C.CString(serAddress), C.CString(serCustClose), C.CString(serMerchState)))
	r := processCResponse(resp)
	return r.Wpk, r.MerchClose, r.Error
}

func BidirectionalWtpVerifyCustCloseMessage(serChannelToken string, serWpk string, serCloseMsg string, serCloseToken string) string {
	resp := C.GoString(C.ffishim_bidirectional_wtp_verify_cust_close_message(C.CString(serChannelToken), C.CString(serWpk), C.CString(serCloseMsg), C.CString(serCloseToken)))
	r := processCResponse(resp)
	return r.Result
}

func BidirectionalWtpVerifyMerchCloseMessage(serChannelToken string, serWpk string, serMerchClose string) string {
	resp := C.GoString(C.ffishim_bidirectional_wtp_verify_merch_close_message(C.CString(serChannelToken), C.CString(serWpk), C.CString(serMerchClose)))
	r := processCResponse(resp)
	return r.Result
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

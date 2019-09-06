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

type MerchState struct {
	KeyPair     KeyPair     `json:"keypair"`
	InitBalance int         `json:"init_balance"`
	Pk          string      `json:"pk"`
	Sk          string      `json:"sk"`
	ComParams   ComParams   `json:"comParams"`
	Keys        interface{} `json:"keys"`
	PayTokens   interface{} `json:"pay_tokens"`
}

type CustState struct {
	Name         string               `json:"name"`
	PkC          string               `json:"pk_c"`
	SkC          string               `json:"sk_c"`
	CustBalance  int                  `json:"cust_balance"`
	MerchBalance int                  `json:"merch_balance"`
	Wpk          string               `json:"wpk"`
	Wsk          string               `json:"wsk"`
	OldKP        *KP                  `json:"old_kp,omitempty"`
	T            []uint64             `json:"t"`
	Wallet       Wallet               `json:"wallet"`
	WCom         Commitment           `json:"w_com"`
	Index        int                  `json:"index"`
	CloseTokens  map[string]Signature `json:"close_tokens"`
	PayTokens    map[string]Signature `json:"pay_tokens"`
}

type KP struct {
	Wpk string `json:"wpk,omitempty"`
	Wsk string `json:"wsk,omitempty"`
}

type Commitment struct {
	C string `json:"c"`
}

type Wallet struct {
	Pkc   []uint64 `json:"pkc"`
	Wpk   []uint64 `json:"wpk"`
	Bc    int      `json:"bc"`
	Bm    int      `json:"bm"`
	Close []uint64 `json:"close"`
}

type KeyPair struct {
	Secret SecretKey `json:"secret"`
	Public PublicKey `json:"public"`
}

type SecretKey struct {
	X []uint64   `json:"x"`
	Y [][]uint64 `json:"y"`
}

type PublicKey struct {
	X1 string   `json:"X1"`
	X2 string   `json:"X2"`
	Y1 []string `json:"Y1"`
	Y2 []string `json:"Y2"`
}

type PublicKeySingle struct {
	X string   `json:"X"`
	Y []string `json:"Y"`
}

type ComParams struct {
	PubBases []string `json:"pub_bases"`
}

type Signature struct {
	H1 string `json:"h"`
	H2 string `json:"H"`
}

type ChannelToken struct {
	Pkc       *string         `json:"pk_c"`
	Pkm       string          `json:"pk_m"`
	ClPkM     PublicKeySingle `json:"cl_pk_m"`
	Mpk       MPK             `json:"mpk"`
	ComParams ComParams       `json:"comParams"`
}

type MPK struct {
	G1 string `json:"g1"`
	G2 string `json:"g2"`
}

type RevokeToken struct {
	Message   Message `json:"message"`
	Signature string  `json:"signature"`
}

type Message struct {
	Type string `json:"msgtype"`
	Wpk  string `json:"wpk"`
}

type CommitmentProof struct {
	T      string     `json:"T"`
	Z      [][]uint64 `json:"z"`
	Ts     [][]uint64 `json:"t"`
	Index  []int      `json:"index"`
	Reveal [][]uint64 `json:"reveal"`
}

type CustClose struct {
	Wpk       string    `json:"wpk"`
	Message   Wallet    `json:"message"`
	Signature Signature `json:"signature"`
}

func BidirectionalChannelSetup(name string, channelSupport bool) string {
	resp := C.GoString(C.ffishim_bidirectional_channel_setup(C.CString(name), C.uint(btoi(channelSupport))))
	r := processCResponse(resp)
	return r.ChannelState
}

func BidirectionalInitMerchant(channelState string, balanceMerchant int, nameMerchant string) (ChannelToken, MerchState) {
	resp := C.GoString(C.ffishim_bidirectional_init_merchant(C.CString(channelState), C.int(balanceMerchant), C.CString(nameMerchant)))
	r := processCResponse(resp)
	merchState := MerchState{}
	json.Unmarshal([]byte(r.MerchState), &merchState)
	channelToken := ChannelToken{}
	json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	return channelToken, merchState
}

func BidirectionalInitCustomer(channelState string, channelToken ChannelToken, balanceCustomer int, balanceMerchant int, nameCustomer string) (ChannelToken, CustState) {
	serChannelToken, _ := json.Marshal(channelToken)
	resp := C.GoString(C.ffishim_bidirectional_init_customer(C.CString(channelState), C.CString(string(serChannelToken)), C.int(balanceCustomer), C.int(balanceMerchant), C.CString(nameCustomer)))
	r := processCResponse(resp)
	custState := CustState{}
	json.Unmarshal([]byte(r.CustState), &custState)
	json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	return channelToken, custState
}

func BidirectionalEstablishCustomerGenerateProof(channelToken ChannelToken, custState CustState) (ChannelToken, CustState, Commitment, CommitmentProof) {
	serChannelToken, _ := json.Marshal(channelToken)
	serCustState, _ := json.Marshal(custState)
	resp := C.GoString(C.ffishim_bidirectional_establish_customer_generate_proof(C.CString(string(serChannelToken)), C.CString(string(serCustState))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.CustState), &custState)
	json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	com := Commitment{}
	json.Unmarshal([]byte(r.Com), &com)
	comProof := CommitmentProof{}
	json.Unmarshal([]byte(r.ComProof), &comProof)
	return channelToken, custState, com, comProof
}

func BidirectionalEstablishMerchantIssueCloseToken(serChannelState string, com Commitment, comProof CommitmentProof, initCustBal int, initMerchBal int, merchState MerchState) Signature {
	serCom, _ := json.Marshal(com)
	serMerchState, _ := json.Marshal(merchState)
	serComProof, _ := json.Marshal(comProof)
	resp := C.GoString(C.ffishim_bidirectional_establish_merchant_issue_close_token(C.CString(serChannelState), C.CString(string(serCom)), C.CString(string(serComProof)), C.int(initCustBal), C.int(initMerchBal), C.CString(string(serMerchState))))
	r := processCResponse(resp)
	closeToken := &Signature{}
	json.Unmarshal([]byte(r.CloseToken), closeToken)
	return *closeToken
}

func BidirectionalEstablishMerchantIssuePayToken(serChannelState string, com Commitment, merchState MerchState) Signature {
	serCom, _ := json.Marshal(com)
	serMerchState, _ := json.Marshal(merchState)
	resp := C.GoString(C.ffishim_bidirectional_establish_merchant_issue_pay_token(C.CString(serChannelState), C.CString(string(serCom)), C.CString(string(serMerchState))))
	r := processCResponse(resp)
	payToken := &Signature{}
	json.Unmarshal([]byte(r.PayToken), payToken)
	return *payToken
}

func BidirectionalVerifyCloseToken(serChannelState string, custState CustState, closeToken Signature) (bool, string, CustState) {
	serCloseToken, _ := json.Marshal(closeToken)
	serCustState, _ := json.Marshal(custState)
	resp := C.GoString(C.ffishim_bidirectional_verify_close_token(C.CString(serChannelState), C.CString(string(serCustState)), C.CString(string(serCloseToken))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsTokenValid, r.ChannelState, custState
}

func BidirectionalEstablishCustomerFinal(serChannelState string, custState CustState, payToken Signature) (bool, string, CustState) {
	serPayToken, _ := json.Marshal(payToken)
	serCustState, _ := json.Marshal(custState)
	resp := C.GoString(C.ffishim_bidirectional_establish_customer_final(C.CString(serChannelState), C.CString(string(serCustState)), C.CString(string(serPayToken))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsEstablished, r.ChannelState, custState
}

func BidirectionalPayGeneratePaymentProof(serChannelState string, custState CustState, amount int) (string, CustState) {
	serCustState, _ := json.Marshal(custState)
	resp := C.GoString(C.ffishim_bidirectional_pay_generate_payment_proof(C.CString(serChannelState), C.CString(string(serCustState)), C.int(amount)))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.CustState), &custState)
	return r.Payment, custState
}

func BidirectionalPayVerifyPaymentProof(serChannelState string, serPayProof string, merchState MerchState) (Signature, MerchState) {
	serMerchState, _ := json.Marshal(merchState)
	resp := C.GoString(C.ffishim_bidirectional_pay_verify_payment_proof(C.CString(serChannelState), C.CString(serPayProof), C.CString(string(serMerchState))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.MerchState), &merchState)
	closeToken := &Signature{}
	json.Unmarshal([]byte(r.CloseToken), closeToken)
	return *closeToken, merchState
}

func BidirectionalPayGenerateRevokeToken(serChannelState string, custState CustState, newCustState CustState, closeToken Signature) (RevokeToken, CustState) {
	serCloseToken, _ := json.Marshal(closeToken)
	serCustState, _ := json.Marshal(custState)
	serNewCustState, _ := json.Marshal(newCustState)
	resp := C.GoString(C.ffishim_bidirectional_pay_generate_revoke_token(C.CString(serChannelState), C.CString(string(serCustState)), C.CString(string(serNewCustState)), C.CString(string(serCloseToken))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.CustState), &custState)
	revokeToken := RevokeToken{}
	json.Unmarshal([]byte(r.RevokeToken), &revokeToken)
	return revokeToken, custState
}

func BidirectionalPayVerifyRevokeToken(revokeToken RevokeToken, merchState MerchState) (Signature, MerchState) {
	serMerchState, _ := json.Marshal(merchState)
	serRevokeToken, _ := json.Marshal(revokeToken)
	resp := C.GoString(C.ffishim_bidirectional_pay_verify_revoke_token(C.CString(string(serRevokeToken)), C.CString(string(serMerchState))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.MerchState), &merchState)
	payToken := &Signature{}
	json.Unmarshal([]byte(r.PayToken), payToken)
	return *payToken, merchState
}

func BidirectionalPayVerifyPaymentToken(serChannelState string, custState CustState, payToken Signature) (CustState, bool) {
	serPayToken, _ := json.Marshal(payToken)
	serCustState, _ := json.Marshal(custState)
	resp := C.GoString(C.ffishim_bidirectional_pay_verify_payment_token(C.CString(serChannelState), C.CString(string(serCustState)), C.CString(string(serPayToken))))
	r := processCResponse(resp)
	json.Unmarshal([]byte(r.CustState), &custState)
	return custState, r.IsPayValid
}

func BidirectionalCustomerClose(serChannelState string, custState CustState) CustClose {
	serCustState, _ := json.Marshal(custState)
	resp := C.GoString(C.ffishim_bidirectional_customer_close(C.CString(serChannelState), C.CString(string(serCustState))))
	r := processCResponse(resp)
	custClose:= CustClose{}
	json.Unmarshal([]byte(r.CustClose), &custClose)
	return custClose
}

func BidirectionalMerchantClose(serChannelState string, channelToken ChannelToken, serAddress string, custClose CustClose, merchState MerchState) (string, string, string) {
	serMerchState, _ := json.Marshal(merchState)
	serChannelToken, _ := json.Marshal(channelToken)
	serCustClose, _ := json.Marshal(custClose)
	resp := C.GoString(C.ffishim_bidirectional_merchant_close(C.CString(serChannelState), C.CString(string(serChannelToken)), C.CString(serAddress), C.CString(string(serCustClose)), C.CString(string(serMerchState))))
	r := processCResponse(resp)
	return r.Wpk, r.MerchClose, r.Error
}

func BidirectionalWtpVerifyCustCloseMessage(channelToken ChannelToken, serWpk string, serCloseMsg string, serCloseToken string) string {
	serChannelToken, _ := json.Marshal(channelToken)
	resp := C.GoString(C.ffishim_bidirectional_wtp_verify_cust_close_message(C.CString(string(serChannelToken)), C.CString(serWpk), C.CString(serCloseMsg), C.CString(string(serCloseToken))))
	r := processCResponse(resp)
	return r.Result
}

func BidirectionalWtpVerifyMerchCloseMessage(channelToken ChannelToken, serWpk string, serMerchClose string) string {
	serChannelToken, _ := json.Marshal(channelToken)
	resp := C.GoString(C.ffishim_bidirectional_wtp_verify_merch_close_message(C.CString(string(serChannelToken)), C.CString(serWpk), C.CString(serMerchClose)))
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

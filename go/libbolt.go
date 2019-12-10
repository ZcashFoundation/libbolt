package main

// #cgo CFLAGS: -I ../include -D LD_LIBRARY_PATH=../target/release
// #cgo LDFLAGS: -L ../target/release/ -lbolt
// #include <libbolt.h>
import "C"
import (
	"encoding/json"
	"strings"
	"fmt"
)

type setupResp struct {
	ChannelState           string `json:"channel_state"`
	ChannelToken           string `json:"channel_token"`
	CustState              string `json:"cust_state"`
	MerchState             string `json:"merch_state"`
	Com                    string `json:"com"`
	ComProof               string `json:"com_proof"`
	IsTokenValid           bool   `json:"is_token_valid,string"`
	IsEstablished          bool   `json:"is_established,string"`
	IsPayValid             bool   `json:"is_pay_valid,string"`
	Payment                string `json:"payment"`
	CloseToken             string `json:"close_token"`
	SenderCloseToken       string `json:"sender_close_token"`
	ReceiverCondCloseToken string `json:"receiver_cond_close_token"`
	RevokeToken            string `json:"revoke_token"`
	PayToken               string `json:"pay_token"`
	SenderPayToken         string `json:"sender_pay_token"`
	ReceiverPayToken       string `json:"receiver_pay_token"`
	CustClose              string `json:"cust_close"`
	MerchClose             string `json:"merch_close"`
	Wpk                    string `json:"wpk"`
	Error                  string `json:"error"`
	Result                 string `json:"result"`
}

type ChannelState struct {
	R                  int            `json:"R"`
	TxFee              int64          `json:"tx_fee"`
	Cp                 *ChannelParams `json:"cp"`
	Name               string         `json:"name"`
	PayInit            bool           `json:"pay_init"`
	ChannelEstablished bool           `json:"channel_established"`
	ThirdParty         bool           `json:"third_party"`
}

type ChannelParams struct {
	ExtraVerify bool      `json:"extra_verify"`
	L           int64     `json:"l"`
	PubParams   PubParams `json:"pub_params"`
}

type PubParams struct {
	ComParams ComParams   `json:"comParams"`
	Mpk       MPK         `json:"mpk"`
	Pk        PublicKey   `json:"pk"`
	RpParams  RpPubParams `json:"rpParams"`
}

type RpPubParams struct {
	ComParams  ComParams            `json:"csParams"`
	L          int64                `json:"l"`
	U          int64                `json:"u"`
	Mpk        MPK                  `json:"mpk"`
	Pk         PublicKey            `json:"pk"`
	Signatures map[string]Signature `json:"signatures"`
}

type MerchState struct {
	Id         string                `json:"id"`
	KeyPair    KeyPair               `json:"keypair"`
	NizkParams NIZKParams            `json:"nizkParams"`
	Pk         string                `json:"pk"`
	Sk         string                `json:"sk"`
	ComParams  ComParams             `json:"comParams"`
	Keys       map[string]RevokedKey `json:"keys"`
	PayTokens  map[string]Signature  `json:"pay_tokens"`
}

type RevokedKey struct {
	Wpk         string  `json:"wpk"`
	RevokeToken *string `json:"revoke_token"`
}

type NIZKParams struct {
	PubParams PubParams `json:"pubParams"`
	KeyPair   KeyPair   `json:"keypair"`
	RpParams  RpParams  `json:"rpParams"`
}

type RpParams struct {
	PubParams RpPubParams `json:"pubParams"`
	KeyPair   KeyPair     `json:"kp"`
}

type CustState struct {
	Name         string               `json:"name"`
	PkC          string               `json:"pk_c"`
	SkC          string               `json:"sk_c"`
	CustBalance  int64                `json:"cust_balance"`
	MerchBalance int64                `json:"merch_balance"`
	Wpk          string               `json:"wpk"`
	Wsk          string               `json:"wsk"`
	OldKP        *KP                  `json:"old_kp,omitempty"`
	T            []string             `json:"t"`
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
	ChannelId []string `json:"channelId"`
	Wpk       []string `json:"wpk"`
	Bc        int64    `json:"bc"`
	Bm        int64    `json:"bm"`
	Close     []string `json:"close"`
}

type KeyPair struct {
	Secret SecretKey `json:"secret"`
	Public PublicKey `json:"public"`
}

type SecretKey struct {
	X []string   `json:"x"`
	Y [][]string `json:"y"`
}

type Payment struct {
	Proof  Proof      `json:"proof"`
	Com    Commitment `json:"com"`
	Wpk    string     `json:"wpk"`
	Amount int64      `json:"amount"`
}

type Proof struct {
	Sig          Signature       `json:"sig"`
	SigProof     SigProof        `json:"sigProof"`
	ComProof     CommitmentProof `json:"comProof"`
	RangeProofBC RangeProof      `json:"rpBC"`
	RangeProofBM RangeProof      `json:"rpBM"`
}

type SigProof struct {
	Zsig [][]string  `json:"zsig"`
	Zv   []string    `json:"zv"`
	A    interface{} `json:"a"`
}

type RangeProof struct {
	V         []Signature `json:"V"`
	D         string      `json:"D"`
	Com       Commitment  `json:"comm"`
	SigProofs []SigProof  `json:"sigProofs"`
	Zr        []string    `json:"zr"`
	Zs        [][]string  `json:"zs"`
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
	Z      [][]string `json:"z"`
	Ts     [][]string `json:"t"`
	Index  []int      `json:"index"`
	Reveal [][]string `json:"reveal"`
}

type CustClose struct {
	Wpk       string    `json:"wpk"`
	Message   Wallet    `json:"message"`
	Signature Signature `json:"signature"`
}

type ZkChannelParams struct {
	Commitment      Commitment	`json:"commitment"`
	CommitmentProof CommitmentProof	`json:"commproof"`
	CustPkC         string		`json:"custstatepkc"`
}

func BidirectionalChannelSetup(name string, channelSupport bool) (ChannelState, error) {
	resp := C.GoString(C.ffishim_bls12_channel_setup(C.CString(name), C.uint(btoi(channelSupport))))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelState{}, err
	}
	channelState := ChannelState{}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	return channelState, err
}

func BidirectionalInitMerchant(channelState ChannelState, nameMerchant string) (ChannelToken, MerchState, ChannelState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return ChannelToken{}, MerchState{}, ChannelState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_init_merchant(C.CString(string(serChannelState)), C.CString(nameMerchant)))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelToken{}, MerchState{}, ChannelState{}, err
	}
	merchState := MerchState{}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	if err != nil {
		return ChannelToken{}, MerchState{}, ChannelState{}, err
	}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return ChannelToken{}, MerchState{}, ChannelState{}, err
	}
	channelToken := ChannelToken{}
	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	return channelToken, merchState, channelState, err
}

func BidirectionalInitCustomer(channelToken ChannelToken, balanceCustomer int, balanceMerchant int, nameCustomer string) (ChannelToken, CustState, error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_init_customer(C.CString(string(serChannelToken)), C.longlong(balanceCustomer), C.longlong(balanceMerchant), C.CString(nameCustomer)))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}
	custState := CustState{}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	return channelToken, custState, err
}

func BidirectionalEstablishCustomerGenerateProof(channelToken ChannelToken, custState CustState) (ChannelToken, CustState, Commitment, CommitmentProof, error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return ChannelToken{}, CustState{}, Commitment{}, CommitmentProof{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return ChannelToken{}, CustState{}, Commitment{}, CommitmentProof{}, err
	}
	resp := C.GoString(C.ffishim_bls12_establish_customer_generate_proof(C.CString(string(serChannelToken)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelToken{}, CustState{}, Commitment{}, CommitmentProof{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	if err != nil {
		return ChannelToken{}, CustState{}, Commitment{}, CommitmentProof{}, err
	}
	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	if err != nil {
		return ChannelToken{}, CustState{}, Commitment{}, CommitmentProof{}, err
	}
	com := Commitment{}
	err = json.Unmarshal([]byte(r.Com), &com)
	if err != nil {
		return ChannelToken{}, CustState{}, Commitment{}, CommitmentProof{}, err
	}
	comProof := CommitmentProof{}
	err = json.Unmarshal([]byte(r.ComProof), &comProof)
	return channelToken, custState, com, comProof, err
}



func BidirectionalGenerateChannelID(channelToken ChannelToken) (error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
            return err
        }
	resp := C.GoString(C.ffishim_bls12_generate_channel_id(C.CString(string(serChannelToken))))
	r, err := processCResponse(resp)
	if err != nil {
	    return err
	}
	fmt.Println("channel id: ", r)
	return err
}



func BidirectionalEstablishMerchantIssueCloseToken(channelState ChannelState, com Commitment, comProof CommitmentProof, channelId []string, initCustBal int, initMerchBal int, merchState MerchState) (Signature, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return Signature{}, err
	}
	serCom, err := json.Marshal(com)
	if err != nil {
		return Signature{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return Signature{}, err
	}
	serComProof, err := json.Marshal(comProof)
	if err != nil {
		return Signature{}, err
	}
	serChannelId, err := json.Marshal(channelId)
	if err != nil {
		return Signature{}, err
	}
	resp := C.GoString(C.ffishim_bls12_establish_merchant_issue_close_token(C.CString(string(serChannelState)), C.CString(string(serCom)), C.CString(string(serComProof)), C.CString(string(serChannelId)), C.longlong(initCustBal), C.longlong(initMerchBal), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return Signature{}, err
	}
	closeToken := Signature{}
	err = json.Unmarshal([]byte(r.CloseToken), &closeToken)
	return closeToken, err
}

func BidirectionalEstablishMerchantIssuePayToken(channelState ChannelState, com Commitment, merchState MerchState) (Signature, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return Signature{}, err
	}
	serCom, err := json.Marshal(com)
	if err != nil {
		return Signature{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return Signature{}, err
	}
	resp := C.GoString(C.ffishim_bls12_establish_merchant_issue_pay_token(C.CString(string(serChannelState)), C.CString(string(serCom)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return Signature{}, err
	}
	payToken := Signature{}
	err = json.Unmarshal([]byte(r.PayToken), &payToken)
	return payToken, err
}

func BidirectionalVerifyCloseToken(channelState ChannelState, custState CustState, closeToken Signature) (bool, ChannelState, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	serCloseToken, err := json.Marshal(closeToken)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_verify_close_token(C.CString(string(serChannelState)), C.CString(string(serCustState)), C.CString(string(serCloseToken))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsTokenValid, channelState, custState, err
}

func BidirectionalEstablishCustomerFinal(channelState ChannelState, custState CustState, payToken Signature) (bool, ChannelState, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	serPayToken, err := json.Marshal(payToken)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_establish_customer_final(C.CString(string(serChannelState)), C.CString(string(serCustState)), C.CString(string(serPayToken))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return false, ChannelState{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsEstablished, channelState, custState, err
}

func BidirectionalPayGeneratePaymentProof(channelState ChannelState, custState CustState, amount int) (Payment, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return Payment{}, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return Payment{}, CustState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_generate_payment_proof(C.CString(string(serChannelState)), C.CString(string(serCustState)), C.longlong(amount)))
	r, err := processCResponse(resp)
	if err != nil {
		return Payment{}, CustState{}, err
	}
	payProof := Payment{}
	err = json.Unmarshal([]byte(r.Payment), &payProof)
	if err != nil {
		return Payment{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return payProof, custState, err
}

func BidirectionalPayVerifyPaymentProof(channelState ChannelState, payProof Payment, merchState MerchState) (Signature, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	serPayProof, err := json.Marshal(payProof)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_verify_payment_proof(C.CString(string(serChannelState)), C.CString(string(serPayProof)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	closeToken := &Signature{}
	err = json.Unmarshal([]byte(r.CloseToken), closeToken)
	return *closeToken, merchState, err
}

func BidirectionalPayVerifyMultiplePaymentProofs(channelState ChannelState, senderPayProof Payment, receiverPayProof Payment, merchState MerchState) (Signature, Signature, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	serSenderPayProof, err := json.Marshal(senderPayProof)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	serReceiverPayProof, err := json.Marshal(receiverPayProof)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_verify_multiple_payment_proofs(C.CString(string(serChannelState)), C.CString(string(serSenderPayProof)), C.CString(string(serReceiverPayProof)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	senderCloseToken := &Signature{}
	err = json.Unmarshal([]byte(r.SenderCloseToken), senderCloseToken)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	receiverCondCloseToken := &Signature{}
	err = json.Unmarshal([]byte(r.ReceiverCondCloseToken), receiverCondCloseToken)
	return *senderCloseToken, *receiverCondCloseToken, merchState, err
}

func BidirectionalPayGenerateRevokeToken(channelState ChannelState, custState CustState, newCustState CustState, closeToken Signature) (RevokeToken, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return RevokeToken{}, CustState{}, err
	}
	serCloseToken, err := json.Marshal(closeToken)
	if err != nil {
		return RevokeToken{}, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return RevokeToken{}, CustState{}, err
	}
	serNewCustState, err := json.Marshal(newCustState)
	if err != nil {
		return RevokeToken{}, CustState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_generate_revoke_token(C.CString(string(serChannelState)), C.CString(string(serCustState)), C.CString(string(serNewCustState)), C.CString(string(serCloseToken))))
	r, err := processCResponse(resp)
	if err != nil {
		return RevokeToken{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	if err != nil {
		return RevokeToken{}, CustState{}, err
	}
	revokeToken := RevokeToken{}
	err = json.Unmarshal([]byte(r.RevokeToken), &revokeToken)
	return revokeToken, custState, err
}

func BidirectionalPayVerifyRevokeToken(revokeToken RevokeToken, merchState MerchState) (Signature, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	serRevokeToken, err := json.Marshal(revokeToken)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_verify_revoke_token(C.CString(string(serRevokeToken)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	if err != nil {
		return Signature{}, MerchState{}, err
	}
	payToken := &Signature{}
	err = json.Unmarshal([]byte(r.PayToken), payToken)
	return *payToken, merchState, err
}

func BidirectionalPayVerifyMultipleRevokeTokens(senderRevokeToken RevokeToken, receiverRevokeToken RevokeToken, merchState MerchState) (Signature, Signature, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	serSenderRevokeToken, err := json.Marshal(senderRevokeToken)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	serReceiverRevokeToken, err := json.Marshal(receiverRevokeToken)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_verify_multiple_revoke_tokens(C.CString(string(serSenderRevokeToken)), C.CString(string(serReceiverRevokeToken)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	senderPayToken := &Signature{}
	err = json.Unmarshal([]byte(r.SenderPayToken), senderPayToken)
	if err != nil {
		return Signature{}, Signature{}, MerchState{}, err
	}
	receiverPayToken := &Signature{}
	err = json.Unmarshal([]byte(r.ReceiverPayToken), receiverPayToken)
	return *senderPayToken, *receiverPayToken, merchState, err
}

func BidirectionalPayVerifyPaymentToken(channelState ChannelState, custState CustState, payToken Signature) (CustState, bool, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return CustState{}, false, err
	}
	serPayToken, err := json.Marshal(payToken)
	if err != nil {
		return CustState{}, false, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return CustState{}, false, err
	}
	resp := C.GoString(C.ffishim_bls12_pay_verify_payment_token(C.CString(string(serChannelState)), C.CString(string(serCustState)), C.CString(string(serPayToken))))
	r, err := processCResponse(resp)
	if err != nil {
		return CustState{}, false, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return custState, r.IsPayValid, err
}

func BidirectionalCustomerClose(channelState ChannelState, custState CustState) (CustClose, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return CustClose{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return CustClose{}, err
	}
	resp := C.GoString(C.ffishim_bls12_customer_close(C.CString(string(serChannelState)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return CustClose{}, err
	}
	custClose := CustClose{}
	err = json.Unmarshal([]byte(r.CustClose), &custClose)
	return custClose, err
}

func BidirectionalMerchantClose(channelState ChannelState, channelToken ChannelToken, serAddress string, custClose CustClose, merchState MerchState) (string, string, string, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", "", "", err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", "", err
	}
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", "", "", err
	}
	serCustClose, err := json.Marshal(custClose)
	if err != nil {
		return "", "", "", err
	}
	resp := C.GoString(C.ffishim_bls12_merchant_close(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.CString(serAddress), C.CString(string(serCustClose)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", err
	}
	return r.Wpk, r.MerchClose, r.Error, nil
}

func BidirectionalWtpVerifyCustCloseMessage(channelToken ChannelToken, serWpk string, serCloseMsg string, serCloseToken string) (string, error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", err
	}
	resp := C.GoString(C.ffishim_bls12_wtp_verify_cust_close_message(C.CString(string(serChannelToken)), C.CString(serWpk), C.CString(serCloseMsg), C.CString(string(serCloseToken))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}
	return r.Result, nil
}

func BidirectionalWtpVerifyMerchCloseMessage(channelToken ChannelToken, serWpk string, serMerchClose string) (string, error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", err
	}
	resp := C.GoString(C.ffishim_bls12_wtp_verify_merch_close_message(C.CString(string(serChannelToken)), C.CString(serWpk), C.CString(serMerchClose)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}
	return r.Result, nil
}

func processCResponse(resp string) (*setupResp, error) {
	resp = cleanJson(resp)
	r := &setupResp{}
	err := json.Unmarshal([]byte(resp), r)
	return r, err
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

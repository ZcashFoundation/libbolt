package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ChannelSetup(t *testing.T) {
	_, channelToken, merchState, custState, err := setup(1000, 100)
	assert.Nil(t, err)

	assert.NotEqual(t, MerchState{}, merchState)
	assert.NotEqual(t, CustState{}, custState)
	assert.NotEqual(t, ChannelToken{}, channelToken)
}

func setup(b0Cust int, b0Merch int) (ChannelState, ChannelToken, MerchState, CustState, error) {
	channelState, err := BidirectionalChannelSetup("Test Channel", false)
	if err != nil {
		return ChannelState{}, ChannelToken{}, MerchState{}, CustState{}, err
	}
	channelToken, merchState, channelState, err := BidirectionalInitMerchant(channelState, "Bob")
	if err != nil {
		return ChannelState{}, ChannelToken{}, MerchState{}, CustState{}, err
	}
	channelToken, custState, err := BidirectionalInitCustomer(channelToken, b0Cust, b0Merch, "Alice")
	return channelState, channelToken, merchState, custState, err
}

func Test_Establish(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState, err := setup(b0Cust, b0Merch)
	assert.Nil(t, err)

	channelToken, custState, com, comProof, err := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	assert.Nil(t, err)

	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, custState.Wallet.ChannelId, b0Cust, b0Merch, merchState)
	assert.Nil(t, err)
	assert.NotNil(t, closeToken)

	isTokenValid, channelState, custState, err := BidirectionalVerifyCloseToken(channelState, custState, closeToken)
	assert.Nil(t, err)
	assert.True(t, isTokenValid)

	payToken, err := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	assert.Nil(t, err)
	assert.NotNil(t, payToken)

	isChannelEstablished, channelState, custState, err := BidirectionalEstablishCustomerFinal(channelState, custState, payToken)
	assert.Nil(t, err)

	assert.True(t, isChannelEstablished)
}

func Test_Pay(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState, err := setup(b0Cust, b0Merch)
	assert.Nil(t, err)
	channelToken, custState, com, comProof, err := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	assert.Nil(t, err)
	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, custState.Wallet.ChannelId, b0Cust, b0Merch, merchState)
	assert.Nil(t, err)
	_, channelState, custState, err = BidirectionalVerifyCloseToken(channelState, custState, closeToken)
	assert.Nil(t, err)
	payToken, err := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	assert.Nil(t, err)
	_, channelState, custState, err = BidirectionalEstablishCustomerFinal(channelState, custState, payToken)
	assert.Nil(t, err)

	payment, newCustState, err := BidirectionalPayGeneratePaymentProof(channelState, custState, 10)
	assert.Nil(t, err)
	closeToken, merchState, err = BidirectionalPayVerifyPaymentProof(channelState, payment, merchState)
	assert.Nil(t, err)
	revokeToken, custState, err := BidirectionalPayGenerateRevokeToken(channelState, custState, newCustState, closeToken)
	assert.Nil(t, err)
	payToken, merchState, err = BidirectionalPayVerifyRevokeToken(revokeToken, merchState)
	assert.Nil(t, err)
	custState, isTokenValid, err := BidirectionalPayVerifyPaymentToken(channelState, custState, payToken)
	assert.Nil(t, err)
	assert.True(t, isTokenValid)
}

func Test_IntermediaryPay(t *testing.T) {
	b0Alice := 1000
	b0Bob := 100
	b0Intermediary := 100
	channelState, err := BidirectionalChannelSetup("Test Channel", false)
	assert.Nil(t, err)
	channelToken, merchState, channelState, err := BidirectionalInitMerchant(channelState, "Hub")
	assert.Nil(t, err)
	channelToken, custStateAlice, err := BidirectionalInitCustomer(channelToken, b0Alice, b0Intermediary, "Alice")
	assert.Nil(t, err)
	channelToken, custStateAlice, com, comProof, err := BidirectionalEstablishCustomerGenerateProof(channelToken, custStateAlice)
	assert.Nil(t, err)
	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, custStateAlice.Wallet.ChannelId, b0Alice, b0Intermediary, merchState)
	assert.Nil(t, err)
	_, channelState, custStateAlice, err = BidirectionalVerifyCloseToken(channelState, custStateAlice, closeToken)
	assert.Nil(t, err)
	payToken, err := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	assert.Nil(t, err)
	_, channelState, custStateAlice, err = BidirectionalEstablishCustomerFinal(channelState, custStateAlice, payToken)
	assert.Nil(t, err)
	channelToken, custStateBob, err := BidirectionalInitCustomer(channelToken, b0Bob, b0Intermediary, "Bob")
	assert.Nil(t, err)
	channelToken, custStateBob, com, comProof, err = BidirectionalEstablishCustomerGenerateProof(channelToken, custStateBob)
	assert.Nil(t, err)
	closeToken, err = BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, custStateBob.Wallet.ChannelId, b0Bob, b0Intermediary, merchState)
	assert.Nil(t, err)
	_, channelState, custStateBob, err = BidirectionalVerifyCloseToken(channelState, custStateBob, closeToken)
	assert.Nil(t, err)
	payToken, err = BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	assert.Nil(t, err)
	_, channelState, custStateBob, err = BidirectionalEstablishCustomerFinal(channelState, custStateBob, payToken)
	assert.Nil(t, err)

	paymentA, newCustStateAlice, err := BidirectionalPayGeneratePaymentProof(channelState, custStateAlice, 10)
	assert.Nil(t, err)
	paymentB, newCustStateBob, err := BidirectionalPayGeneratePaymentProof(channelState, custStateBob, -10)
	assert.Nil(t, err)
	closeTokenA, closeTokenB, merchState, err := BidirectionalPayVerifyMultiplePaymentProofs(channelState, paymentA, paymentB, merchState)
	assert.Nil(t, err)
	revokeTokenA, custStateAlice, err := BidirectionalPayGenerateRevokeToken(channelState, custStateAlice, newCustStateAlice, closeTokenA)
	assert.Nil(t, err)
	revokeTokenB, custStateBob, err := BidirectionalPayGenerateRevokeToken(channelState, custStateBob, newCustStateBob, closeTokenB)
	assert.Nil(t, err)
	payTokenA, payTokenB, merchState, err := BidirectionalPayVerifyMultipleRevokeTokens(revokeTokenA, revokeTokenB, merchState)
	assert.Nil(t, err)
	custStateAlice, isTokenValid, err := BidirectionalPayVerifyPaymentToken(channelState, custStateAlice, payTokenA)
	assert.Nil(t, err)
	assert.True(t, isTokenValid)
	custStateBob, isTokenValid, err = BidirectionalPayVerifyPaymentToken(channelState, custStateBob, payTokenB)
	assert.Nil(t, err)
	assert.True(t, isTokenValid)
}

func Test_Close(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState, err := setup(b0Cust, b0Merch)
	assert.Nil(t, err)
	channelToken, custState, com, comProof, err := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	assert.Nil(t, err)
	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, custState.Wallet.ChannelId, b0Cust, b0Merch, merchState)
	assert.Nil(t, err)
	_, channelState, custState, err = BidirectionalVerifyCloseToken(channelState, custState, closeToken)
	assert.Nil(t, err)
	payToken, err := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	assert.Nil(t, err)
	_, channelState, custState, err = BidirectionalEstablishCustomerFinal(channelState, custState, payToken)
	assert.Nil(t, err)

	payment, newCustState, err := BidirectionalPayGeneratePaymentProof(channelState, custState, 10)
	assert.Nil(t, err)
	closeToken, merchState, err = BidirectionalPayVerifyPaymentProof(channelState, payment, merchState)
	assert.Nil(t, err)
	revokeToken, custState, err := BidirectionalPayGenerateRevokeToken(channelState, custState, newCustState, closeToken)
	assert.Nil(t, err)
	payToken, merchState, err = BidirectionalPayVerifyRevokeToken(revokeToken, merchState)
	assert.Nil(t, err)
	custState, _, err = BidirectionalPayVerifyPaymentToken(channelState, custState, payToken)
	assert.Nil(t, err)

	custClose, err := BidirectionalCustomerClose(channelState, custState)
	assert.Nil(t, err)
	_, _, Err, err := BidirectionalMerchantClose(channelState, channelToken, "onChainAddress", custClose, merchState)
	assert.Nil(t, err)
	assert.Equal(t, "merchant_close - Could not find entry for wpk & revoke token pair. Valid close!", Err)
}


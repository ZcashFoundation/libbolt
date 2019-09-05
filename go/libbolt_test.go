package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ChannelSetup(t *testing.T) {
	_, channelToken, merchState, custState := setup(1000, 100)

	assert.NotEqual(t, "", merchState)
	assert.NotEqual(t, "", custState)
	assert.NotEqual(t, "", channelToken)
}

func setup(b0Cust int, b0Merch int) (string, string, string, string) {
	channelState := BidirectionalChannelSetup("Test Channel", false)
	channelToken, merchState := BidirectionalInitMerchant(channelState, b0Merch, "Bob")
	channelToken, custState := BidirectionalInitCustomer(channelState, channelToken, b0Cust, b0Merch, "Alice")
	return channelState, channelToken, merchState, custState
}

func Test_Establish(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState := setup(b0Cust, b0Merch)

	channelToken, custState, com, comProof := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)

	closeToken := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, b0Cust, b0Merch, merchState)
	assert.NotNil(t, closeToken)

	isTokenValid, channelState, custState := BidirectionalVerifyCloseToken(channelState, custState, closeToken)
	assert.True(t, isTokenValid)

	payToken := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	assert.NotNil(t, payToken)

	isChannelEstablished, channelState, custState := BidirectionalEstablishCustomerFinal(channelState, custState, payToken)

	assert.True(t, isChannelEstablished)
}

func Test_Pay(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState := setup(b0Cust, b0Merch)
	channelToken, custState, com, comProof := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	closeToken := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, b0Cust, b0Merch, merchState)
	_, channelState, custState = BidirectionalVerifyCloseToken(channelState, custState, closeToken)
	payToken := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	_, channelState, custState = BidirectionalEstablishCustomerFinal(channelState, custState, payToken)

	payment, newCustState := BidirectionalPayGeneratePaymentProof(channelState, custState, 10)
	closeToken, merchState = BidirectionalPayVerifyPaymentProof(channelState, payment, merchState)
	revokeToken, custState := BidirectionalPayGenerateRevokeToken(channelState, custState, newCustState, closeToken)
	payToken, merchState = BidirectionalPayVerifyRevokeToken(revokeToken, merchState)
	custState, isTokenValid := BidirectionalPayVerifyPaymentToken(channelState, custState, payToken)
	assert.True(t, isTokenValid)
}

func Test_Close(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState := setup(b0Cust, b0Merch)
	channelToken, custState, com, comProof := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	closeToken := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, b0Cust, b0Merch, merchState)
	_, channelState, custState = BidirectionalVerifyCloseToken(channelState, custState, closeToken)
	payToken := BidirectionalEstablishMerchantIssuePayToken(channelState, com, merchState)
	_, channelState, custState = BidirectionalEstablishCustomerFinal(channelState, custState, payToken)

	payment, newCustState := BidirectionalPayGeneratePaymentProof(channelState, custState, 10)
	closeToken, merchState = BidirectionalPayVerifyPaymentProof(channelState, payment, merchState)
	revokeToken, custState := BidirectionalPayGenerateRevokeToken(channelState, custState, newCustState, closeToken)
	payToken, merchState = BidirectionalPayVerifyRevokeToken(revokeToken, merchState)
	custState, _ = BidirectionalPayVerifyPaymentToken(channelState, custState, payToken)

	custClose := BidirectionalCustomerClose(channelState, custState)
	_, _, err := BidirectionalMerchantClose(channelState, channelToken, "onChainAddress", custClose, merchState)
	assert.Equal(t, "merchant_close - Could not find entry for wpk & revoke token pair. Valid close!", err)
}


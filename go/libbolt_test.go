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

func setup(b0Cust int, b0Merch int) (string, ChannelToken, MerchState, CustState, error) {
	channelState, err := BidirectionalChannelSetup("Test Channel", false)
	if err != nil {
		return "", ChannelToken{}, MerchState{}, CustState{}, err
	}
	channelToken, merchState, err := BidirectionalInitMerchant(channelState, b0Merch, "Bob")
	if err != nil {
		return "", ChannelToken{}, MerchState{}, CustState{}, err
	}
	channelToken, custState, err := BidirectionalInitCustomer(channelState, channelToken, b0Cust, b0Merch, "Alice")
	return channelState, channelToken, merchState, custState, err
}

func Test_Establish(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState, err := setup(b0Cust, b0Merch)
	assert.Nil(t, err)

	channelToken, custState, com, comProof, err := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	assert.Nil(t, err)

	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, b0Cust, b0Merch, merchState)
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
	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, b0Cust, b0Merch, merchState)
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

func Test_Close(t *testing.T) {
	b0Cust := 1000
	b0Merch := 100
	channelState, channelToken, merchState, custState, err := setup(b0Cust, b0Merch)
	assert.Nil(t, err)
	channelToken, custState, com, comProof, err := BidirectionalEstablishCustomerGenerateProof(channelToken, custState)
	assert.Nil(t, err)
	closeToken, err := BidirectionalEstablishMerchantIssueCloseToken(channelState, com, comProof, b0Cust, b0Merch, merchState)
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


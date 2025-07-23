# BursaWallet

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Mnemonic** | Pointer to **string** |  | [optional] 
**PaymentAddress** | Pointer to **string** |  | [optional] 
**PaymentExtendedSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**PaymentSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**PaymentVkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**StakeAddress** | Pointer to **string** |  | [optional] 
**StakeExtendedSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**StakeSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**StakeVkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 

## Methods

### NewBursaWallet

`func NewBursaWallet() *BursaWallet`

NewBursaWallet instantiates a new BursaWallet object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBursaWalletWithDefaults

`func NewBursaWalletWithDefaults() *BursaWallet`

NewBursaWalletWithDefaults instantiates a new BursaWallet object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMnemonic

`func (o *BursaWallet) GetMnemonic() string`

GetMnemonic returns the Mnemonic field if non-nil, zero value otherwise.

### GetMnemonicOk

`func (o *BursaWallet) GetMnemonicOk() (*string, bool)`

GetMnemonicOk returns a tuple with the Mnemonic field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMnemonic

`func (o *BursaWallet) SetMnemonic(v string)`

SetMnemonic sets Mnemonic field to given value.

### HasMnemonic

`func (o *BursaWallet) HasMnemonic() bool`

HasMnemonic returns a boolean if a field has been set.

### GetPaymentAddress

`func (o *BursaWallet) GetPaymentAddress() string`

GetPaymentAddress returns the PaymentAddress field if non-nil, zero value otherwise.

### GetPaymentAddressOk

`func (o *BursaWallet) GetPaymentAddressOk() (*string, bool)`

GetPaymentAddressOk returns a tuple with the PaymentAddress field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPaymentAddress

`func (o *BursaWallet) SetPaymentAddress(v string)`

SetPaymentAddress sets PaymentAddress field to given value.

### HasPaymentAddress

`func (o *BursaWallet) HasPaymentAddress() bool`

HasPaymentAddress returns a boolean if a field has been set.

### GetPaymentExtendedSkey

`func (o *BursaWallet) GetPaymentExtendedSkey() BursaKeyFile`

GetPaymentExtendedSkey returns the PaymentExtendedSkey field if non-nil, zero value otherwise.

### GetPaymentExtendedSkeyOk

`func (o *BursaWallet) GetPaymentExtendedSkeyOk() (*BursaKeyFile, bool)`

GetPaymentExtendedSkeyOk returns a tuple with the PaymentExtendedSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPaymentExtendedSkey

`func (o *BursaWallet) SetPaymentExtendedSkey(v BursaKeyFile)`

SetPaymentExtendedSkey sets PaymentExtendedSkey field to given value.

### HasPaymentExtendedSkey

`func (o *BursaWallet) HasPaymentExtendedSkey() bool`

HasPaymentExtendedSkey returns a boolean if a field has been set.

### GetPaymentSkey

`func (o *BursaWallet) GetPaymentSkey() BursaKeyFile`

GetPaymentSkey returns the PaymentSkey field if non-nil, zero value otherwise.

### GetPaymentSkeyOk

`func (o *BursaWallet) GetPaymentSkeyOk() (*BursaKeyFile, bool)`

GetPaymentSkeyOk returns a tuple with the PaymentSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPaymentSkey

`func (o *BursaWallet) SetPaymentSkey(v BursaKeyFile)`

SetPaymentSkey sets PaymentSkey field to given value.

### HasPaymentSkey

`func (o *BursaWallet) HasPaymentSkey() bool`

HasPaymentSkey returns a boolean if a field has been set.

### GetPaymentVkey

`func (o *BursaWallet) GetPaymentVkey() BursaKeyFile`

GetPaymentVkey returns the PaymentVkey field if non-nil, zero value otherwise.

### GetPaymentVkeyOk

`func (o *BursaWallet) GetPaymentVkeyOk() (*BursaKeyFile, bool)`

GetPaymentVkeyOk returns a tuple with the PaymentVkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPaymentVkey

`func (o *BursaWallet) SetPaymentVkey(v BursaKeyFile)`

SetPaymentVkey sets PaymentVkey field to given value.

### HasPaymentVkey

`func (o *BursaWallet) HasPaymentVkey() bool`

HasPaymentVkey returns a boolean if a field has been set.

### GetStakeAddress

`func (o *BursaWallet) GetStakeAddress() string`

GetStakeAddress returns the StakeAddress field if non-nil, zero value otherwise.

### GetStakeAddressOk

`func (o *BursaWallet) GetStakeAddressOk() (*string, bool)`

GetStakeAddressOk returns a tuple with the StakeAddress field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStakeAddress

`func (o *BursaWallet) SetStakeAddress(v string)`

SetStakeAddress sets StakeAddress field to given value.

### HasStakeAddress

`func (o *BursaWallet) HasStakeAddress() bool`

HasStakeAddress returns a boolean if a field has been set.

### GetStakeExtendedSkey

`func (o *BursaWallet) GetStakeExtendedSkey() BursaKeyFile`

GetStakeExtendedSkey returns the StakeExtendedSkey field if non-nil, zero value otherwise.

### GetStakeExtendedSkeyOk

`func (o *BursaWallet) GetStakeExtendedSkeyOk() (*BursaKeyFile, bool)`

GetStakeExtendedSkeyOk returns a tuple with the StakeExtendedSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStakeExtendedSkey

`func (o *BursaWallet) SetStakeExtendedSkey(v BursaKeyFile)`

SetStakeExtendedSkey sets StakeExtendedSkey field to given value.

### HasStakeExtendedSkey

`func (o *BursaWallet) HasStakeExtendedSkey() bool`

HasStakeExtendedSkey returns a boolean if a field has been set.

### GetStakeSkey

`func (o *BursaWallet) GetStakeSkey() BursaKeyFile`

GetStakeSkey returns the StakeSkey field if non-nil, zero value otherwise.

### GetStakeSkeyOk

`func (o *BursaWallet) GetStakeSkeyOk() (*BursaKeyFile, bool)`

GetStakeSkeyOk returns a tuple with the StakeSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStakeSkey

`func (o *BursaWallet) SetStakeSkey(v BursaKeyFile)`

SetStakeSkey sets StakeSkey field to given value.

### HasStakeSkey

`func (o *BursaWallet) HasStakeSkey() bool`

HasStakeSkey returns a boolean if a field has been set.

### GetStakeVkey

`func (o *BursaWallet) GetStakeVkey() BursaKeyFile`

GetStakeVkey returns the StakeVkey field if non-nil, zero value otherwise.

### GetStakeVkeyOk

`func (o *BursaWallet) GetStakeVkeyOk() (*BursaKeyFile, bool)`

GetStakeVkeyOk returns a tuple with the StakeVkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStakeVkey

`func (o *BursaWallet) SetStakeVkey(v BursaKeyFile)`

SetStakeVkey sets StakeVkey field to given value.

### HasStakeVkey

`func (o *BursaWallet) HasStakeVkey() bool`

HasStakeVkey returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



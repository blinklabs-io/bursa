# BursaWallet

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**CommitteeColdExtendedSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**CommitteeColdSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**CommitteeColdVkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**CommitteeHotExtendedSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**CommitteeHotSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**CommitteeHotVkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**DrepExtendedSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**DrepSkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
**DrepVkey** | Pointer to [**BursaKeyFile**](BursaKeyFile.md) |  | [optional] 
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

### GetCommitteeColdExtendedSkey

`func (o *BursaWallet) GetCommitteeColdExtendedSkey() BursaKeyFile`

GetCommitteeColdExtendedSkey returns the CommitteeColdExtendedSkey field if non-nil, zero value otherwise.

### GetCommitteeColdExtendedSkeyOk

`func (o *BursaWallet) GetCommitteeColdExtendedSkeyOk() (*BursaKeyFile, bool)`

GetCommitteeColdExtendedSkeyOk returns a tuple with the CommitteeColdExtendedSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeColdExtendedSkey

`func (o *BursaWallet) SetCommitteeColdExtendedSkey(v BursaKeyFile)`

SetCommitteeColdExtendedSkey sets CommitteeColdExtendedSkey field to given value.

### HasCommitteeColdExtendedSkey

`func (o *BursaWallet) HasCommitteeColdExtendedSkey() bool`

HasCommitteeColdExtendedSkey returns a boolean if a field has been set.

### GetCommitteeColdSkey

`func (o *BursaWallet) GetCommitteeColdSkey() BursaKeyFile`

GetCommitteeColdSkey returns the CommitteeColdSkey field if non-nil, zero value otherwise.

### GetCommitteeColdSkeyOk

`func (o *BursaWallet) GetCommitteeColdSkeyOk() (*BursaKeyFile, bool)`

GetCommitteeColdSkeyOk returns a tuple with the CommitteeColdSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeColdSkey

`func (o *BursaWallet) SetCommitteeColdSkey(v BursaKeyFile)`

SetCommitteeColdSkey sets CommitteeColdSkey field to given value.

### HasCommitteeColdSkey

`func (o *BursaWallet) HasCommitteeColdSkey() bool`

HasCommitteeColdSkey returns a boolean if a field has been set.

### GetCommitteeColdVkey

`func (o *BursaWallet) GetCommitteeColdVkey() BursaKeyFile`

GetCommitteeColdVkey returns the CommitteeColdVkey field if non-nil, zero value otherwise.

### GetCommitteeColdVkeyOk

`func (o *BursaWallet) GetCommitteeColdVkeyOk() (*BursaKeyFile, bool)`

GetCommitteeColdVkeyOk returns a tuple with the CommitteeColdVkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeColdVkey

`func (o *BursaWallet) SetCommitteeColdVkey(v BursaKeyFile)`

SetCommitteeColdVkey sets CommitteeColdVkey field to given value.

### HasCommitteeColdVkey

`func (o *BursaWallet) HasCommitteeColdVkey() bool`

HasCommitteeColdVkey returns a boolean if a field has been set.

### GetCommitteeHotExtendedSkey

`func (o *BursaWallet) GetCommitteeHotExtendedSkey() BursaKeyFile`

GetCommitteeHotExtendedSkey returns the CommitteeHotExtendedSkey field if non-nil, zero value otherwise.

### GetCommitteeHotExtendedSkeyOk

`func (o *BursaWallet) GetCommitteeHotExtendedSkeyOk() (*BursaKeyFile, bool)`

GetCommitteeHotExtendedSkeyOk returns a tuple with the CommitteeHotExtendedSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeHotExtendedSkey

`func (o *BursaWallet) SetCommitteeHotExtendedSkey(v BursaKeyFile)`

SetCommitteeHotExtendedSkey sets CommitteeHotExtendedSkey field to given value.

### HasCommitteeHotExtendedSkey

`func (o *BursaWallet) HasCommitteeHotExtendedSkey() bool`

HasCommitteeHotExtendedSkey returns a boolean if a field has been set.

### GetCommitteeHotSkey

`func (o *BursaWallet) GetCommitteeHotSkey() BursaKeyFile`

GetCommitteeHotSkey returns the CommitteeHotSkey field if non-nil, zero value otherwise.

### GetCommitteeHotSkeyOk

`func (o *BursaWallet) GetCommitteeHotSkeyOk() (*BursaKeyFile, bool)`

GetCommitteeHotSkeyOk returns a tuple with the CommitteeHotSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeHotSkey

`func (o *BursaWallet) SetCommitteeHotSkey(v BursaKeyFile)`

SetCommitteeHotSkey sets CommitteeHotSkey field to given value.

### HasCommitteeHotSkey

`func (o *BursaWallet) HasCommitteeHotSkey() bool`

HasCommitteeHotSkey returns a boolean if a field has been set.

### GetCommitteeHotVkey

`func (o *BursaWallet) GetCommitteeHotVkey() BursaKeyFile`

GetCommitteeHotVkey returns the CommitteeHotVkey field if non-nil, zero value otherwise.

### GetCommitteeHotVkeyOk

`func (o *BursaWallet) GetCommitteeHotVkeyOk() (*BursaKeyFile, bool)`

GetCommitteeHotVkeyOk returns a tuple with the CommitteeHotVkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeHotVkey

`func (o *BursaWallet) SetCommitteeHotVkey(v BursaKeyFile)`

SetCommitteeHotVkey sets CommitteeHotVkey field to given value.

### HasCommitteeHotVkey

`func (o *BursaWallet) HasCommitteeHotVkey() bool`

HasCommitteeHotVkey returns a boolean if a field has been set.

### GetDrepExtendedSkey

`func (o *BursaWallet) GetDrepExtendedSkey() BursaKeyFile`

GetDrepExtendedSkey returns the DrepExtendedSkey field if non-nil, zero value otherwise.

### GetDrepExtendedSkeyOk

`func (o *BursaWallet) GetDrepExtendedSkeyOk() (*BursaKeyFile, bool)`

GetDrepExtendedSkeyOk returns a tuple with the DrepExtendedSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDrepExtendedSkey

`func (o *BursaWallet) SetDrepExtendedSkey(v BursaKeyFile)`

SetDrepExtendedSkey sets DrepExtendedSkey field to given value.

### HasDrepExtendedSkey

`func (o *BursaWallet) HasDrepExtendedSkey() bool`

HasDrepExtendedSkey returns a boolean if a field has been set.

### GetDrepSkey

`func (o *BursaWallet) GetDrepSkey() BursaKeyFile`

GetDrepSkey returns the DrepSkey field if non-nil, zero value otherwise.

### GetDrepSkeyOk

`func (o *BursaWallet) GetDrepSkeyOk() (*BursaKeyFile, bool)`

GetDrepSkeyOk returns a tuple with the DrepSkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDrepSkey

`func (o *BursaWallet) SetDrepSkey(v BursaKeyFile)`

SetDrepSkey sets DrepSkey field to given value.

### HasDrepSkey

`func (o *BursaWallet) HasDrepSkey() bool`

HasDrepSkey returns a boolean if a field has been set.

### GetDrepVkey

`func (o *BursaWallet) GetDrepVkey() BursaKeyFile`

GetDrepVkey returns the DrepVkey field if non-nil, zero value otherwise.

### GetDrepVkeyOk

`func (o *BursaWallet) GetDrepVkeyOk() (*BursaKeyFile, bool)`

GetDrepVkeyOk returns a tuple with the DrepVkey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDrepVkey

`func (o *BursaWallet) SetDrepVkey(v BursaKeyFile)`

SetDrepVkey sets DrepVkey field to given value.

### HasDrepVkey

`func (o *BursaWallet) HasDrepVkey() bool`

HasDrepVkey returns a boolean if a field has been set.

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



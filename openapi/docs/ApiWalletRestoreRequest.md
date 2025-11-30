# ApiWalletRestoreRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AccountId** | Pointer to **int32** |  | [optional] 
**AddressId** | Pointer to **int32** |  | [optional] 
**CommitteeColdId** | Pointer to **int32** |  | [optional] 
**CommitteeHotId** | Pointer to **int32** |  | [optional] 
**DrepId** | Pointer to **int32** |  | [optional] 
**Mnemonic** | **string** |  | 
**Password** | Pointer to **string** |  | [optional] 
**PaymentId** | Pointer to **int32** |  | [optional] 
**StakeId** | Pointer to **int32** |  | [optional] 

## Methods

### NewApiWalletRestoreRequest

`func NewApiWalletRestoreRequest(mnemonic string, ) *ApiWalletRestoreRequest`

NewApiWalletRestoreRequest instantiates a new ApiWalletRestoreRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiWalletRestoreRequestWithDefaults

`func NewApiWalletRestoreRequestWithDefaults() *ApiWalletRestoreRequest`

NewApiWalletRestoreRequestWithDefaults instantiates a new ApiWalletRestoreRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAccountId

`func (o *ApiWalletRestoreRequest) GetAccountId() int32`

GetAccountId returns the AccountId field if non-nil, zero value otherwise.

### GetAccountIdOk

`func (o *ApiWalletRestoreRequest) GetAccountIdOk() (*int32, bool)`

GetAccountIdOk returns a tuple with the AccountId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAccountId

`func (o *ApiWalletRestoreRequest) SetAccountId(v int32)`

SetAccountId sets AccountId field to given value.

### HasAccountId

`func (o *ApiWalletRestoreRequest) HasAccountId() bool`

HasAccountId returns a boolean if a field has been set.

### GetAddressId

`func (o *ApiWalletRestoreRequest) GetAddressId() int32`

GetAddressId returns the AddressId field if non-nil, zero value otherwise.

### GetAddressIdOk

`func (o *ApiWalletRestoreRequest) GetAddressIdOk() (*int32, bool)`

GetAddressIdOk returns a tuple with the AddressId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddressId

`func (o *ApiWalletRestoreRequest) SetAddressId(v int32)`

SetAddressId sets AddressId field to given value.

### HasAddressId

`func (o *ApiWalletRestoreRequest) HasAddressId() bool`

HasAddressId returns a boolean if a field has been set.

### GetCommitteeColdId

`func (o *ApiWalletRestoreRequest) GetCommitteeColdId() int32`

GetCommitteeColdId returns the CommitteeColdId field if non-nil, zero value otherwise.

### GetCommitteeColdIdOk

`func (o *ApiWalletRestoreRequest) GetCommitteeColdIdOk() (*int32, bool)`

GetCommitteeColdIdOk returns a tuple with the CommitteeColdId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeColdId

`func (o *ApiWalletRestoreRequest) SetCommitteeColdId(v int32)`

SetCommitteeColdId sets CommitteeColdId field to given value.

### HasCommitteeColdId

`func (o *ApiWalletRestoreRequest) HasCommitteeColdId() bool`

HasCommitteeColdId returns a boolean if a field has been set.

### GetCommitteeHotId

`func (o *ApiWalletRestoreRequest) GetCommitteeHotId() int32`

GetCommitteeHotId returns the CommitteeHotId field if non-nil, zero value otherwise.

### GetCommitteeHotIdOk

`func (o *ApiWalletRestoreRequest) GetCommitteeHotIdOk() (*int32, bool)`

GetCommitteeHotIdOk returns a tuple with the CommitteeHotId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitteeHotId

`func (o *ApiWalletRestoreRequest) SetCommitteeHotId(v int32)`

SetCommitteeHotId sets CommitteeHotId field to given value.

### HasCommitteeHotId

`func (o *ApiWalletRestoreRequest) HasCommitteeHotId() bool`

HasCommitteeHotId returns a boolean if a field has been set.

### GetDrepId

`func (o *ApiWalletRestoreRequest) GetDrepId() int32`

GetDrepId returns the DrepId field if non-nil, zero value otherwise.

### GetDrepIdOk

`func (o *ApiWalletRestoreRequest) GetDrepIdOk() (*int32, bool)`

GetDrepIdOk returns a tuple with the DrepId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDrepId

`func (o *ApiWalletRestoreRequest) SetDrepId(v int32)`

SetDrepId sets DrepId field to given value.

### HasDrepId

`func (o *ApiWalletRestoreRequest) HasDrepId() bool`

HasDrepId returns a boolean if a field has been set.

### GetMnemonic

`func (o *ApiWalletRestoreRequest) GetMnemonic() string`

GetMnemonic returns the Mnemonic field if non-nil, zero value otherwise.

### GetMnemonicOk

`func (o *ApiWalletRestoreRequest) GetMnemonicOk() (*string, bool)`

GetMnemonicOk returns a tuple with the Mnemonic field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMnemonic

`func (o *ApiWalletRestoreRequest) SetMnemonic(v string)`

SetMnemonic sets Mnemonic field to given value.


### GetPassword

`func (o *ApiWalletRestoreRequest) GetPassword() string`

GetPassword returns the Password field if non-nil, zero value otherwise.

### GetPasswordOk

`func (o *ApiWalletRestoreRequest) GetPasswordOk() (*string, bool)`

GetPasswordOk returns a tuple with the Password field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassword

`func (o *ApiWalletRestoreRequest) SetPassword(v string)`

SetPassword sets Password field to given value.

### HasPassword

`func (o *ApiWalletRestoreRequest) HasPassword() bool`

HasPassword returns a boolean if a field has been set.

### GetPaymentId

`func (o *ApiWalletRestoreRequest) GetPaymentId() int32`

GetPaymentId returns the PaymentId field if non-nil, zero value otherwise.

### GetPaymentIdOk

`func (o *ApiWalletRestoreRequest) GetPaymentIdOk() (*int32, bool)`

GetPaymentIdOk returns a tuple with the PaymentId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPaymentId

`func (o *ApiWalletRestoreRequest) SetPaymentId(v int32)`

SetPaymentId sets PaymentId field to given value.

### HasPaymentId

`func (o *ApiWalletRestoreRequest) HasPaymentId() bool`

HasPaymentId returns a boolean if a field has been set.

### GetStakeId

`func (o *ApiWalletRestoreRequest) GetStakeId() int32`

GetStakeId returns the StakeId field if non-nil, zero value otherwise.

### GetStakeIdOk

`func (o *ApiWalletRestoreRequest) GetStakeIdOk() (*int32, bool)`

GetStakeIdOk returns a tuple with the StakeId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStakeId

`func (o *ApiWalletRestoreRequest) SetStakeId(v int32)`

SetStakeId sets StakeId field to given value.

### HasStakeId

`func (o *ApiWalletRestoreRequest) HasStakeId() bool`

HasStakeId returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



# ApiAddressEnumerateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Account** | Pointer to **int32** |  | [optional]
**Count** | **int32** |  |
**Mnemonic** | **string** |  |
**Network** | **string** |  |
**Password** | Pointer to **string** |  | [optional]
**Start** | Pointer to **int32** |  | [optional]

## Methods

### NewApiAddressEnumerateRequest

`func NewApiAddressEnumerateRequest(count int32, mnemonic string, network string, ) *ApiAddressEnumerateRequest`

NewApiAddressEnumerateRequest instantiates a new ApiAddressEnumerateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiAddressEnumerateRequestWithDefaults

`func NewApiAddressEnumerateRequestWithDefaults() *ApiAddressEnumerateRequest`

NewApiAddressEnumerateRequestWithDefaults instantiates a new ApiAddressEnumerateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAccount

`func (o *ApiAddressEnumerateRequest) GetAccount() int32`

GetAccount returns the Account field if non-nil, zero value otherwise.

### GetAccountOk

`func (o *ApiAddressEnumerateRequest) GetAccountOk() (*int32, bool)`

GetAccountOk returns a tuple with the Account field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAccount

`func (o *ApiAddressEnumerateRequest) SetAccount(v int32)`

SetAccount sets Account field to given value.

### HasAccount

`func (o *ApiAddressEnumerateRequest) HasAccount() bool`

HasAccount returns a boolean if a field has been set.

### GetCount

`func (o *ApiAddressEnumerateRequest) GetCount() int32`

GetCount returns the Count field if non-nil, zero value otherwise.

### GetCountOk

`func (o *ApiAddressEnumerateRequest) GetCountOk() (*int32, bool)`

GetCountOk returns a tuple with the Count field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCount

`func (o *ApiAddressEnumerateRequest) SetCount(v int32)`

SetCount sets Count field to given value.


### GetMnemonic

`func (o *ApiAddressEnumerateRequest) GetMnemonic() string`

GetMnemonic returns the Mnemonic field if non-nil, zero value otherwise.

### GetMnemonicOk

`func (o *ApiAddressEnumerateRequest) GetMnemonicOk() (*string, bool)`

GetMnemonicOk returns a tuple with the Mnemonic field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMnemonic

`func (o *ApiAddressEnumerateRequest) SetMnemonic(v string)`

SetMnemonic sets Mnemonic field to given value.


### GetNetwork

`func (o *ApiAddressEnumerateRequest) GetNetwork() string`

GetNetwork returns the Network field if non-nil, zero value otherwise.

### GetNetworkOk

`func (o *ApiAddressEnumerateRequest) GetNetworkOk() (*string, bool)`

GetNetworkOk returns a tuple with the Network field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNetwork

`func (o *ApiAddressEnumerateRequest) SetNetwork(v string)`

SetNetwork sets Network field to given value.


### GetPassword

`func (o *ApiAddressEnumerateRequest) GetPassword() string`

GetPassword returns the Password field if non-nil, zero value otherwise.

### GetPasswordOk

`func (o *ApiAddressEnumerateRequest) GetPasswordOk() (*string, bool)`

GetPasswordOk returns a tuple with the Password field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassword

`func (o *ApiAddressEnumerateRequest) SetPassword(v string)`

SetPassword sets Password field to given value.

### HasPassword

`func (o *ApiAddressEnumerateRequest) HasPassword() bool`

HasPassword returns a boolean if a field has been set.

### GetStart

`func (o *ApiAddressEnumerateRequest) GetStart() int32`

GetStart returns the Start field if non-nil, zero value otherwise.

### GetStartOk

`func (o *ApiAddressEnumerateRequest) GetStartOk() (*int32, bool)`

GetStartOk returns a tuple with the Start field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStart

`func (o *ApiAddressEnumerateRequest) SetStart(v int32)`

SetStart sets Start field to given value.

### HasStart

`func (o *ApiAddressEnumerateRequest) HasStart() bool`

HasStart returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

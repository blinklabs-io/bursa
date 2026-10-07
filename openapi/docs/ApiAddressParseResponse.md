# ApiAddressParseResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Address** | Pointer to **string** |  | [optional]
**Byron** | Pointer to [**ApiByronAddressInfo**](ApiByronAddressInfo.md) |  | [optional]
**Network** | Pointer to **string** |  | [optional]
**Payment** | Pointer to [**ApiCredentialInfo**](ApiCredentialInfo.md) |  | [optional]
**Pointer** | Pointer to [**ApiPointerInfo**](ApiPointerInfo.md) |  | [optional]
**Stake** | Pointer to [**ApiCredentialInfo**](ApiCredentialInfo.md) |  | [optional]
**Type** | Pointer to **string** |  | [optional]
**TypeDescription** | Pointer to **string** |  | [optional]

## Methods

### NewApiAddressParseResponse

`func NewApiAddressParseResponse() *ApiAddressParseResponse`

NewApiAddressParseResponse instantiates a new ApiAddressParseResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiAddressParseResponseWithDefaults

`func NewApiAddressParseResponseWithDefaults() *ApiAddressParseResponse`

NewApiAddressParseResponseWithDefaults instantiates a new ApiAddressParseResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAddress

`func (o *ApiAddressParseResponse) GetAddress() string`

GetAddress returns the Address field if non-nil, zero value otherwise.

### GetAddressOk

`func (o *ApiAddressParseResponse) GetAddressOk() (*string, bool)`

GetAddressOk returns a tuple with the Address field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddress

`func (o *ApiAddressParseResponse) SetAddress(v string)`

SetAddress sets Address field to given value.

### HasAddress

`func (o *ApiAddressParseResponse) HasAddress() bool`

HasAddress returns a boolean if a field has been set.

### GetByron

`func (o *ApiAddressParseResponse) GetByron() ApiByronAddressInfo`

GetByron returns the Byron field if non-nil, zero value otherwise.

### GetByronOk

`func (o *ApiAddressParseResponse) GetByronOk() (*ApiByronAddressInfo, bool)`

GetByronOk returns a tuple with the Byron field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetByron

`func (o *ApiAddressParseResponse) SetByron(v ApiByronAddressInfo)`

SetByron sets Byron field to given value.

### HasByron

`func (o *ApiAddressParseResponse) HasByron() bool`

HasByron returns a boolean if a field has been set.

### GetNetwork

`func (o *ApiAddressParseResponse) GetNetwork() string`

GetNetwork returns the Network field if non-nil, zero value otherwise.

### GetNetworkOk

`func (o *ApiAddressParseResponse) GetNetworkOk() (*string, bool)`

GetNetworkOk returns a tuple with the Network field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNetwork

`func (o *ApiAddressParseResponse) SetNetwork(v string)`

SetNetwork sets Network field to given value.

### HasNetwork

`func (o *ApiAddressParseResponse) HasNetwork() bool`

HasNetwork returns a boolean if a field has been set.

### GetPayment

`func (o *ApiAddressParseResponse) GetPayment() ApiCredentialInfo`

GetPayment returns the Payment field if non-nil, zero value otherwise.

### GetPaymentOk

`func (o *ApiAddressParseResponse) GetPaymentOk() (*ApiCredentialInfo, bool)`

GetPaymentOk returns a tuple with the Payment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPayment

`func (o *ApiAddressParseResponse) SetPayment(v ApiCredentialInfo)`

SetPayment sets Payment field to given value.

### HasPayment

`func (o *ApiAddressParseResponse) HasPayment() bool`

HasPayment returns a boolean if a field has been set.

### GetPointer

`func (o *ApiAddressParseResponse) GetPointer() ApiPointerInfo`

GetPointer returns the Pointer field if non-nil, zero value otherwise.

### GetPointerOk

`func (o *ApiAddressParseResponse) GetPointerOk() (*ApiPointerInfo, bool)`

GetPointerOk returns a tuple with the Pointer field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPointer

`func (o *ApiAddressParseResponse) SetPointer(v ApiPointerInfo)`

SetPointer sets Pointer field to given value.

### HasPointer

`func (o *ApiAddressParseResponse) HasPointer() bool`

HasPointer returns a boolean if a field has been set.

### GetStake

`func (o *ApiAddressParseResponse) GetStake() ApiCredentialInfo`

GetStake returns the Stake field if non-nil, zero value otherwise.

### GetStakeOk

`func (o *ApiAddressParseResponse) GetStakeOk() (*ApiCredentialInfo, bool)`

GetStakeOk returns a tuple with the Stake field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStake

`func (o *ApiAddressParseResponse) SetStake(v ApiCredentialInfo)`

SetStake sets Stake field to given value.

### HasStake

`func (o *ApiAddressParseResponse) HasStake() bool`

HasStake returns a boolean if a field has been set.

### GetType

`func (o *ApiAddressParseResponse) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ApiAddressParseResponse) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ApiAddressParseResponse) SetType(v string)`

SetType sets Type field to given value.

### HasType

`func (o *ApiAddressParseResponse) HasType() bool`

HasType returns a boolean if a field has been set.

### GetTypeDescription

`func (o *ApiAddressParseResponse) GetTypeDescription() string`

GetTypeDescription returns the TypeDescription field if non-nil, zero value otherwise.

### GetTypeDescriptionOk

`func (o *ApiAddressParseResponse) GetTypeDescriptionOk() (*string, bool)`

GetTypeDescriptionOk returns a tuple with the TypeDescription field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTypeDescription

`func (o *ApiAddressParseResponse) SetTypeDescription(v string)`

SetTypeDescription sets TypeDescription field to given value.

### HasTypeDescription

`func (o *ApiAddressParseResponse) HasTypeDescription() bool`

HasTypeDescription returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

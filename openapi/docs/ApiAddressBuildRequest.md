# ApiAddressBuildRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Network** | **string** |  |
**PaymentKey** | Pointer to **string** | bech32-encoded verification key (required for base and enterprise address types) | [optional]
**StakeKey** | Pointer to **string** | bech32-encoded verification key (required for base and reward address types) | [optional]
**Type** | Pointer to **string** | defaults to \&quot;base\&quot; - determines which keys are required: base requires both paymentKey and stakeKey, enterprise requires paymentKey only, reward requires stakeKey only | [optional]

## Methods

### NewApiAddressBuildRequest

`func NewApiAddressBuildRequest(network string, ) *ApiAddressBuildRequest`

NewApiAddressBuildRequest instantiates a new ApiAddressBuildRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiAddressBuildRequestWithDefaults

`func NewApiAddressBuildRequestWithDefaults() *ApiAddressBuildRequest`

NewApiAddressBuildRequestWithDefaults instantiates a new ApiAddressBuildRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNetwork

`func (o *ApiAddressBuildRequest) GetNetwork() string`

GetNetwork returns the Network field if non-nil, zero value otherwise.

### GetNetworkOk

`func (o *ApiAddressBuildRequest) GetNetworkOk() (*string, bool)`

GetNetworkOk returns a tuple with the Network field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNetwork

`func (o *ApiAddressBuildRequest) SetNetwork(v string)`

SetNetwork sets Network field to given value.


### GetPaymentKey

`func (o *ApiAddressBuildRequest) GetPaymentKey() string`

GetPaymentKey returns the PaymentKey field if non-nil, zero value otherwise.

### GetPaymentKeyOk

`func (o *ApiAddressBuildRequest) GetPaymentKeyOk() (*string, bool)`

GetPaymentKeyOk returns a tuple with the PaymentKey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPaymentKey

`func (o *ApiAddressBuildRequest) SetPaymentKey(v string)`

SetPaymentKey sets PaymentKey field to given value.

### HasPaymentKey

`func (o *ApiAddressBuildRequest) HasPaymentKey() bool`

HasPaymentKey returns a boolean if a field has been set.

### GetStakeKey

`func (o *ApiAddressBuildRequest) GetStakeKey() string`

GetStakeKey returns the StakeKey field if non-nil, zero value otherwise.

### GetStakeKeyOk

`func (o *ApiAddressBuildRequest) GetStakeKeyOk() (*string, bool)`

GetStakeKeyOk returns a tuple with the StakeKey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStakeKey

`func (o *ApiAddressBuildRequest) SetStakeKey(v string)`

SetStakeKey sets StakeKey field to given value.

### HasStakeKey

`func (o *ApiAddressBuildRequest) HasStakeKey() bool`

HasStakeKey returns a boolean if a field has been set.

### GetType

`func (o *ApiAddressBuildRequest) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ApiAddressBuildRequest) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ApiAddressBuildRequest) SetType(v string)`

SetType sets Type field to given value.

### HasType

`func (o *ApiAddressBuildRequest) HasType() bool`

HasType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# ApiCredentialInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Bech32** | Pointer to **string** | bech32-encoded credential | [optional]
**Hex** | Pointer to **string** | hex-encoded credential | [optional]
**Type** | Pointer to **string** | \&quot;key\&quot; or \&quot;script\&quot; | [optional]

## Methods

### NewApiCredentialInfo

`func NewApiCredentialInfo() *ApiCredentialInfo`

NewApiCredentialInfo instantiates a new ApiCredentialInfo object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiCredentialInfoWithDefaults

`func NewApiCredentialInfoWithDefaults() *ApiCredentialInfo`

NewApiCredentialInfoWithDefaults instantiates a new ApiCredentialInfo object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetBech32

`func (o *ApiCredentialInfo) GetBech32() string`

GetBech32 returns the Bech32 field if non-nil, zero value otherwise.

### GetBech32Ok

`func (o *ApiCredentialInfo) GetBech32Ok() (*string, bool)`

GetBech32Ok returns a tuple with the Bech32 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBech32

`func (o *ApiCredentialInfo) SetBech32(v string)`

SetBech32 sets Bech32 field to given value.

### HasBech32

`func (o *ApiCredentialInfo) HasBech32() bool`

HasBech32 returns a boolean if a field has been set.

### GetHex

`func (o *ApiCredentialInfo) GetHex() string`

GetHex returns the Hex field if non-nil, zero value otherwise.

### GetHexOk

`func (o *ApiCredentialInfo) GetHexOk() (*string, bool)`

GetHexOk returns a tuple with the Hex field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHex

`func (o *ApiCredentialInfo) SetHex(v string)`

SetHex sets Hex field to given value.

### HasHex

`func (o *ApiCredentialInfo) HasHex() bool`

HasHex returns a boolean if a field has been set.

### GetType

`func (o *ApiCredentialInfo) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ApiCredentialInfo) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ApiCredentialInfo) SetType(v string)`

SetType sets Type field to given value.

### HasType

`func (o *ApiCredentialInfo) HasType() bool`

HasType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# ApiScriptCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**KeyHashes** | **[]string** |  | 
**Network** | **string** |  | 
**Required** | Pointer to **int32** |  | [optional] 
**TimelockAfter** | Pointer to **int64** |  | [optional] 
**TimelockBefore** | Pointer to **int64** |  | [optional] 
**Type** | **string** |  | 

## Methods

### NewApiScriptCreateRequest

`func NewApiScriptCreateRequest(keyHashes []string, network string, type_ string, ) *ApiScriptCreateRequest`

NewApiScriptCreateRequest instantiates a new ApiScriptCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiScriptCreateRequestWithDefaults

`func NewApiScriptCreateRequestWithDefaults() *ApiScriptCreateRequest`

NewApiScriptCreateRequestWithDefaults instantiates a new ApiScriptCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetKeyHashes

`func (o *ApiScriptCreateRequest) GetKeyHashes() []string`

GetKeyHashes returns the KeyHashes field if non-nil, zero value otherwise.

### GetKeyHashesOk

`func (o *ApiScriptCreateRequest) GetKeyHashesOk() (*[]string, bool)`

GetKeyHashesOk returns a tuple with the KeyHashes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKeyHashes

`func (o *ApiScriptCreateRequest) SetKeyHashes(v []string)`

SetKeyHashes sets KeyHashes field to given value.


### GetNetwork

`func (o *ApiScriptCreateRequest) GetNetwork() string`

GetNetwork returns the Network field if non-nil, zero value otherwise.

### GetNetworkOk

`func (o *ApiScriptCreateRequest) GetNetworkOk() (*string, bool)`

GetNetworkOk returns a tuple with the Network field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNetwork

`func (o *ApiScriptCreateRequest) SetNetwork(v string)`

SetNetwork sets Network field to given value.


### GetRequired

`func (o *ApiScriptCreateRequest) GetRequired() int32`

GetRequired returns the Required field if non-nil, zero value otherwise.

### GetRequiredOk

`func (o *ApiScriptCreateRequest) GetRequiredOk() (*int32, bool)`

GetRequiredOk returns a tuple with the Required field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequired

`func (o *ApiScriptCreateRequest) SetRequired(v int32)`

SetRequired sets Required field to given value.

### HasRequired

`func (o *ApiScriptCreateRequest) HasRequired() bool`

HasRequired returns a boolean if a field has been set.

### GetTimelockAfter

`func (o *ApiScriptCreateRequest) GetTimelockAfter() int64`

GetTimelockAfter returns the TimelockAfter field if non-nil, zero value otherwise.

### GetTimelockAfterOk

`func (o *ApiScriptCreateRequest) GetTimelockAfterOk() (*int64, bool)`

GetTimelockAfterOk returns a tuple with the TimelockAfter field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimelockAfter

`func (o *ApiScriptCreateRequest) SetTimelockAfter(v int64)`

SetTimelockAfter sets TimelockAfter field to given value.

### HasTimelockAfter

`func (o *ApiScriptCreateRequest) HasTimelockAfter() bool`

HasTimelockAfter returns a boolean if a field has been set.

### GetTimelockBefore

`func (o *ApiScriptCreateRequest) GetTimelockBefore() int64`

GetTimelockBefore returns the TimelockBefore field if non-nil, zero value otherwise.

### GetTimelockBeforeOk

`func (o *ApiScriptCreateRequest) GetTimelockBeforeOk() (*int64, bool)`

GetTimelockBeforeOk returns a tuple with the TimelockBefore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimelockBefore

`func (o *ApiScriptCreateRequest) SetTimelockBefore(v int64)`

SetTimelockBefore sets TimelockBefore field to given value.

### HasTimelockBefore

`func (o *ApiScriptCreateRequest) HasTimelockBefore() bool`

HasTimelockBefore returns a boolean if a field has been set.

### GetType

`func (o *ApiScriptCreateRequest) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ApiScriptCreateRequest) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ApiScriptCreateRequest) SetType(v string)`

SetType sets Type field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



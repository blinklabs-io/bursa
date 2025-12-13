# ApiScriptResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Address** | Pointer to **string** |  | [optional] 
**Script** | Pointer to **map[string]map[string]interface{}** |  | [optional] 
**ScriptHash** | Pointer to **string** |  | [optional] 
**Type** | Pointer to **string** |  | [optional] 

## Methods

### NewApiScriptResponse

`func NewApiScriptResponse() *ApiScriptResponse`

NewApiScriptResponse instantiates a new ApiScriptResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiScriptResponseWithDefaults

`func NewApiScriptResponseWithDefaults() *ApiScriptResponse`

NewApiScriptResponseWithDefaults instantiates a new ApiScriptResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAddress

`func (o *ApiScriptResponse) GetAddress() string`

GetAddress returns the Address field if non-nil, zero value otherwise.

### GetAddressOk

`func (o *ApiScriptResponse) GetAddressOk() (*string, bool)`

GetAddressOk returns a tuple with the Address field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddress

`func (o *ApiScriptResponse) SetAddress(v string)`

SetAddress sets Address field to given value.

### HasAddress

`func (o *ApiScriptResponse) HasAddress() bool`

HasAddress returns a boolean if a field has been set.

### GetScript

`func (o *ApiScriptResponse) GetScript() map[string]map[string]interface{}`

GetScript returns the Script field if non-nil, zero value otherwise.

### GetScriptOk

`func (o *ApiScriptResponse) GetScriptOk() (*map[string]map[string]interface{}, bool)`

GetScriptOk returns a tuple with the Script field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScript

`func (o *ApiScriptResponse) SetScript(v map[string]map[string]interface{})`

SetScript sets Script field to given value.

### HasScript

`func (o *ApiScriptResponse) HasScript() bool`

HasScript returns a boolean if a field has been set.

### GetScriptHash

`func (o *ApiScriptResponse) GetScriptHash() string`

GetScriptHash returns the ScriptHash field if non-nil, zero value otherwise.

### GetScriptHashOk

`func (o *ApiScriptResponse) GetScriptHashOk() (*string, bool)`

GetScriptHashOk returns a tuple with the ScriptHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScriptHash

`func (o *ApiScriptResponse) SetScriptHash(v string)`

SetScriptHash sets ScriptHash field to given value.

### HasScriptHash

`func (o *ApiScriptResponse) HasScriptHash() bool`

HasScriptHash returns a boolean if a field has been set.

### GetType

`func (o *ApiScriptResponse) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ApiScriptResponse) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ApiScriptResponse) SetType(v string)`

SetType sets Type field to given value.

### HasType

`func (o *ApiScriptResponse) HasType() bool`

HasType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



# ApiScriptAddressRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Network** | **string** |  | 
**Script** | **map[string]map[string]interface{}** |  | 

## Methods

### NewApiScriptAddressRequest

`func NewApiScriptAddressRequest(network string, script map[string]map[string]interface{}, ) *ApiScriptAddressRequest`

NewApiScriptAddressRequest instantiates a new ApiScriptAddressRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiScriptAddressRequestWithDefaults

`func NewApiScriptAddressRequestWithDefaults() *ApiScriptAddressRequest`

NewApiScriptAddressRequestWithDefaults instantiates a new ApiScriptAddressRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNetwork

`func (o *ApiScriptAddressRequest) GetNetwork() string`

GetNetwork returns the Network field if non-nil, zero value otherwise.

### GetNetworkOk

`func (o *ApiScriptAddressRequest) GetNetworkOk() (*string, bool)`

GetNetworkOk returns a tuple with the Network field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNetwork

`func (o *ApiScriptAddressRequest) SetNetwork(v string)`

SetNetwork sets Network field to given value.


### GetScript

`func (o *ApiScriptAddressRequest) GetScript() map[string]map[string]interface{}`

GetScript returns the Script field if non-nil, zero value otherwise.

### GetScriptOk

`func (o *ApiScriptAddressRequest) GetScriptOk() (*map[string]map[string]interface{}, bool)`

GetScriptOk returns a tuple with the Script field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScript

`func (o *ApiScriptAddressRequest) SetScript(v map[string]map[string]interface{})`

SetScript sets Script field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



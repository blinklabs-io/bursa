# ApiScriptValidateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**RequireSignatures** | Pointer to **bool** |  | [optional] 
**Script** | **map[string]map[string]interface{}** |  | 
**Signatures** | Pointer to **[]string** |  | [optional] 
**Slot** | Pointer to **int64** |  | [optional] 

## Methods

### NewApiScriptValidateRequest

`func NewApiScriptValidateRequest(script map[string]map[string]interface{}, ) *ApiScriptValidateRequest`

NewApiScriptValidateRequest instantiates a new ApiScriptValidateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiScriptValidateRequestWithDefaults

`func NewApiScriptValidateRequestWithDefaults() *ApiScriptValidateRequest`

NewApiScriptValidateRequestWithDefaults instantiates a new ApiScriptValidateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRequireSignatures

`func (o *ApiScriptValidateRequest) GetRequireSignatures() bool`

GetRequireSignatures returns the RequireSignatures field if non-nil, zero value otherwise.

### GetRequireSignaturesOk

`func (o *ApiScriptValidateRequest) GetRequireSignaturesOk() (*bool, bool)`

GetRequireSignaturesOk returns a tuple with the RequireSignatures field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireSignatures

`func (o *ApiScriptValidateRequest) SetRequireSignatures(v bool)`

SetRequireSignatures sets RequireSignatures field to given value.

### HasRequireSignatures

`func (o *ApiScriptValidateRequest) HasRequireSignatures() bool`

HasRequireSignatures returns a boolean if a field has been set.

### GetScript

`func (o *ApiScriptValidateRequest) GetScript() map[string]map[string]interface{}`

GetScript returns the Script field if non-nil, zero value otherwise.

### GetScriptOk

`func (o *ApiScriptValidateRequest) GetScriptOk() (*map[string]map[string]interface{}, bool)`

GetScriptOk returns a tuple with the Script field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScript

`func (o *ApiScriptValidateRequest) SetScript(v map[string]map[string]interface{})`

SetScript sets Script field to given value.


### GetSignatures

`func (o *ApiScriptValidateRequest) GetSignatures() []string`

GetSignatures returns the Signatures field if non-nil, zero value otherwise.

### GetSignaturesOk

`func (o *ApiScriptValidateRequest) GetSignaturesOk() (*[]string, bool)`

GetSignaturesOk returns a tuple with the Signatures field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignatures

`func (o *ApiScriptValidateRequest) SetSignatures(v []string)`

SetSignatures sets Signatures field to given value.

### HasSignatures

`func (o *ApiScriptValidateRequest) HasSignatures() bool`

HasSignatures returns a boolean if a field has been set.

### GetSlot

`func (o *ApiScriptValidateRequest) GetSlot() int64`

GetSlot returns the Slot field if non-nil, zero value otherwise.

### GetSlotOk

`func (o *ApiScriptValidateRequest) GetSlotOk() (*int64, bool)`

GetSlotOk returns a tuple with the Slot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSlot

`func (o *ApiScriptValidateRequest) SetSlot(v int64)`

SetSlot sets Slot field to given value.

### HasSlot

`func (o *ApiScriptValidateRequest) HasSlot() bool`

HasSlot returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



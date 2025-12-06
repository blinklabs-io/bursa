# ApiScriptValidateResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ScriptHash** | Pointer to **string** |  | [optional] 
**Signatures** | Pointer to **int32** |  | [optional] 
**Slot** | Pointer to **int64** |  | [optional] 
**Valid** | Pointer to **bool** |  | [optional] 

## Methods

### NewApiScriptValidateResponse

`func NewApiScriptValidateResponse() *ApiScriptValidateResponse`

NewApiScriptValidateResponse instantiates a new ApiScriptValidateResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiScriptValidateResponseWithDefaults

`func NewApiScriptValidateResponseWithDefaults() *ApiScriptValidateResponse`

NewApiScriptValidateResponseWithDefaults instantiates a new ApiScriptValidateResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetScriptHash

`func (o *ApiScriptValidateResponse) GetScriptHash() string`

GetScriptHash returns the ScriptHash field if non-nil, zero value otherwise.

### GetScriptHashOk

`func (o *ApiScriptValidateResponse) GetScriptHashOk() (*string, bool)`

GetScriptHashOk returns a tuple with the ScriptHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScriptHash

`func (o *ApiScriptValidateResponse) SetScriptHash(v string)`

SetScriptHash sets ScriptHash field to given value.

### HasScriptHash

`func (o *ApiScriptValidateResponse) HasScriptHash() bool`

HasScriptHash returns a boolean if a field has been set.

### GetSignatures

`func (o *ApiScriptValidateResponse) GetSignatures() int32`

GetSignatures returns the Signatures field if non-nil, zero value otherwise.

### GetSignaturesOk

`func (o *ApiScriptValidateResponse) GetSignaturesOk() (*int32, bool)`

GetSignaturesOk returns a tuple with the Signatures field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignatures

`func (o *ApiScriptValidateResponse) SetSignatures(v int32)`

SetSignatures sets Signatures field to given value.

### HasSignatures

`func (o *ApiScriptValidateResponse) HasSignatures() bool`

HasSignatures returns a boolean if a field has been set.

### GetSlot

`func (o *ApiScriptValidateResponse) GetSlot() int64`

GetSlot returns the Slot field if non-nil, zero value otherwise.

### GetSlotOk

`func (o *ApiScriptValidateResponse) GetSlotOk() (*int64, bool)`

GetSlotOk returns a tuple with the Slot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSlot

`func (o *ApiScriptValidateResponse) SetSlot(v int64)`

SetSlot sets Slot field to given value.

### HasSlot

`func (o *ApiScriptValidateResponse) HasSlot() bool`

HasSlot returns a boolean if a field has been set.

### GetValid

`func (o *ApiScriptValidateResponse) GetValid() bool`

GetValid returns the Valid field if non-nil, zero value otherwise.

### GetValidOk

`func (o *ApiScriptValidateResponse) GetValidOk() (*bool, bool)`

GetValidOk returns a tuple with the Valid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetValid

`func (o *ApiScriptValidateResponse) SetValid(v bool)`

SetValid sets Valid field to given value.

### HasValid

`func (o *ApiScriptValidateResponse) HasValid() bool`

HasValid returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



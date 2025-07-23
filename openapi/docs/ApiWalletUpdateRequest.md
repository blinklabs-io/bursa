# ApiWalletUpdateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Description** | Pointer to **string** |  | [optional] 
**Name** | **string** |  | 
**Password** | Pointer to **string** |  | [optional] 

## Methods

### NewApiWalletUpdateRequest

`func NewApiWalletUpdateRequest(name string, ) *ApiWalletUpdateRequest`

NewApiWalletUpdateRequest instantiates a new ApiWalletUpdateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiWalletUpdateRequestWithDefaults

`func NewApiWalletUpdateRequestWithDefaults() *ApiWalletUpdateRequest`

NewApiWalletUpdateRequestWithDefaults instantiates a new ApiWalletUpdateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetDescription

`func (o *ApiWalletUpdateRequest) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *ApiWalletUpdateRequest) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *ApiWalletUpdateRequest) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *ApiWalletUpdateRequest) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetName

`func (o *ApiWalletUpdateRequest) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *ApiWalletUpdateRequest) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *ApiWalletUpdateRequest) SetName(v string)`

SetName sets Name field to given value.


### GetPassword

`func (o *ApiWalletUpdateRequest) GetPassword() string`

GetPassword returns the Password field if non-nil, zero value otherwise.

### GetPasswordOk

`func (o *ApiWalletUpdateRequest) GetPasswordOk() (*string, bool)`

GetPasswordOk returns a tuple with the Password field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassword

`func (o *ApiWalletUpdateRequest) SetPassword(v string)`

SetPassword sets Password field to given value.

### HasPassword

`func (o *ApiWalletUpdateRequest) HasPassword() bool`

HasPassword returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



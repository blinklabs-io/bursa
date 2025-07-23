# ApiWalletDeleteRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | 
**Password** | Pointer to **string** |  | [optional] 

## Methods

### NewApiWalletDeleteRequest

`func NewApiWalletDeleteRequest(name string, ) *ApiWalletDeleteRequest`

NewApiWalletDeleteRequest instantiates a new ApiWalletDeleteRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiWalletDeleteRequestWithDefaults

`func NewApiWalletDeleteRequestWithDefaults() *ApiWalletDeleteRequest`

NewApiWalletDeleteRequestWithDefaults instantiates a new ApiWalletDeleteRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *ApiWalletDeleteRequest) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *ApiWalletDeleteRequest) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *ApiWalletDeleteRequest) SetName(v string)`

SetName sets Name field to given value.


### GetPassword

`func (o *ApiWalletDeleteRequest) GetPassword() string`

GetPassword returns the Password field if non-nil, zero value otherwise.

### GetPasswordOk

`func (o *ApiWalletDeleteRequest) GetPasswordOk() (*string, bool)`

GetPasswordOk returns a tuple with the Password field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassword

`func (o *ApiWalletDeleteRequest) SetPassword(v string)`

SetPassword sets Password field to given value.

### HasPassword

`func (o *ApiWalletDeleteRequest) HasPassword() bool`

HasPassword returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



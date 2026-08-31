# ApiSignDataResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Key** | Pointer to **string** |  | [optional]
**Signature** | Pointer to **string** |  | [optional]

## Methods

### NewApiSignDataResponse

`func NewApiSignDataResponse() *ApiSignDataResponse`

NewApiSignDataResponse instantiates a new ApiSignDataResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiSignDataResponseWithDefaults

`func NewApiSignDataResponseWithDefaults() *ApiSignDataResponse`

NewApiSignDataResponseWithDefaults instantiates a new ApiSignDataResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetKey

`func (o *ApiSignDataResponse) GetKey() string`

GetKey returns the Key field if non-nil, zero value otherwise.

### GetKeyOk

`func (o *ApiSignDataResponse) GetKeyOk() (*string, bool)`

GetKeyOk returns a tuple with the Key field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKey

`func (o *ApiSignDataResponse) SetKey(v string)`

SetKey sets Key field to given value.

### HasKey

`func (o *ApiSignDataResponse) HasKey() bool`

HasKey returns a boolean if a field has been set.

### GetSignature

`func (o *ApiSignDataResponse) GetSignature() string`

GetSignature returns the Signature field if non-nil, zero value otherwise.

### GetSignatureOk

`func (o *ApiSignDataResponse) GetSignatureOk() (*string, bool)`

GetSignatureOk returns a tuple with the Signature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignature

`func (o *ApiSignDataResponse) SetSignature(v string)`

SetSignature sets Signature field to given value.

### HasSignature

`func (o *ApiSignDataResponse) HasSignature() bool`

HasSignature returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

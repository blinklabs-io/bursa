# ApiVerifyDataRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Key** | **string** |  |
**Payload** | **string** |  |
**Signature** | **string** |  |

## Methods

### NewApiVerifyDataRequest

`func NewApiVerifyDataRequest(key string, payload string, signature string, ) *ApiVerifyDataRequest`

NewApiVerifyDataRequest instantiates a new ApiVerifyDataRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiVerifyDataRequestWithDefaults

`func NewApiVerifyDataRequestWithDefaults() *ApiVerifyDataRequest`

NewApiVerifyDataRequestWithDefaults instantiates a new ApiVerifyDataRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetKey

`func (o *ApiVerifyDataRequest) GetKey() string`

GetKey returns the Key field if non-nil, zero value otherwise.

### GetKeyOk

`func (o *ApiVerifyDataRequest) GetKeyOk() (*string, bool)`

GetKeyOk returns a tuple with the Key field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKey

`func (o *ApiVerifyDataRequest) SetKey(v string)`

SetKey sets Key field to given value.


### GetPayload

`func (o *ApiVerifyDataRequest) GetPayload() string`

GetPayload returns the Payload field if non-nil, zero value otherwise.

### GetPayloadOk

`func (o *ApiVerifyDataRequest) GetPayloadOk() (*string, bool)`

GetPayloadOk returns a tuple with the Payload field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPayload

`func (o *ApiVerifyDataRequest) SetPayload(v string)`

SetPayload sets Payload field to given value.


### GetSignature

`func (o *ApiVerifyDataRequest) GetSignature() string`

GetSignature returns the Signature field if non-nil, zero value otherwise.

### GetSignatureOk

`func (o *ApiVerifyDataRequest) GetSignatureOk() (*string, bool)`

GetSignatureOk returns a tuple with the Signature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignature

`func (o *ApiVerifyDataRequest) SetSignature(v string)`

SetSignature sets Signature field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

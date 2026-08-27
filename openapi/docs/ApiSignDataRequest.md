# ApiSignDataRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Address** | **string** |  |
**Payload** | **string** |  |
**SigningKey** | **string** |  |

## Methods

### NewApiSignDataRequest

`func NewApiSignDataRequest(address string, payload string, signingKey string, ) *ApiSignDataRequest`

NewApiSignDataRequest instantiates a new ApiSignDataRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiSignDataRequestWithDefaults

`func NewApiSignDataRequestWithDefaults() *ApiSignDataRequest`

NewApiSignDataRequestWithDefaults instantiates a new ApiSignDataRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAddress

`func (o *ApiSignDataRequest) GetAddress() string`

GetAddress returns the Address field if non-nil, zero value otherwise.

### GetAddressOk

`func (o *ApiSignDataRequest) GetAddressOk() (*string, bool)`

GetAddressOk returns a tuple with the Address field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddress

`func (o *ApiSignDataRequest) SetAddress(v string)`

SetAddress sets Address field to given value.


### GetPayload

`func (o *ApiSignDataRequest) GetPayload() string`

GetPayload returns the Payload field if non-nil, zero value otherwise.

### GetPayloadOk

`func (o *ApiSignDataRequest) GetPayloadOk() (*string, bool)`

GetPayloadOk returns a tuple with the Payload field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPayload

`func (o *ApiSignDataRequest) SetPayload(v string)`

SetPayload sets Payload field to given value.


### GetSigningKey

`func (o *ApiSignDataRequest) GetSigningKey() string`

GetSigningKey returns the SigningKey field if non-nil, zero value otherwise.

### GetSigningKeyOk

`func (o *ApiSignDataRequest) GetSigningKeyOk() (*string, bool)`

GetSigningKeyOk returns a tuple with the SigningKey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSigningKey

`func (o *ApiSignDataRequest) SetSigningKey(v string)`

SetSigningKey sets SigningKey field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

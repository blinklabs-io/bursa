# ApiTxWitnessRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**SigningKey** | **string** |  |
**TxCbor** | **string** | raw hex CBOR or JSON text envelope |

## Methods

### NewApiTxWitnessRequest

`func NewApiTxWitnessRequest(signingKey string, txCbor string, ) *ApiTxWitnessRequest`

NewApiTxWitnessRequest instantiates a new ApiTxWitnessRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiTxWitnessRequestWithDefaults

`func NewApiTxWitnessRequestWithDefaults() *ApiTxWitnessRequest`

NewApiTxWitnessRequestWithDefaults instantiates a new ApiTxWitnessRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSigningKey

`func (o *ApiTxWitnessRequest) GetSigningKey() string`

GetSigningKey returns the SigningKey field if non-nil, zero value otherwise.

### GetSigningKeyOk

`func (o *ApiTxWitnessRequest) GetSigningKeyOk() (*string, bool)`

GetSigningKeyOk returns a tuple with the SigningKey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSigningKey

`func (o *ApiTxWitnessRequest) SetSigningKey(v string)`

SetSigningKey sets SigningKey field to given value.


### GetTxCbor

`func (o *ApiTxWitnessRequest) GetTxCbor() string`

GetTxCbor returns the TxCbor field if non-nil, zero value otherwise.

### GetTxCborOk

`func (o *ApiTxWitnessRequest) GetTxCborOk() (*string, bool)`

GetTxCborOk returns a tuple with the TxCbor field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCbor

`func (o *ApiTxWitnessRequest) SetTxCbor(v string)`

SetTxCbor sets TxCbor field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

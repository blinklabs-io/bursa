# ApiTxDecodeRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**TxCbor** | **string** | raw hex CBOR or JSON text envelope |

## Methods

### NewApiTxDecodeRequest

`func NewApiTxDecodeRequest(txCbor string, ) *ApiTxDecodeRequest`

NewApiTxDecodeRequest instantiates a new ApiTxDecodeRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiTxDecodeRequestWithDefaults

`func NewApiTxDecodeRequestWithDefaults() *ApiTxDecodeRequest`

NewApiTxDecodeRequestWithDefaults instantiates a new ApiTxDecodeRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTxCbor

`func (o *ApiTxDecodeRequest) GetTxCbor() string`

GetTxCbor returns the TxCbor field if non-nil, zero value otherwise.

### GetTxCborOk

`func (o *ApiTxDecodeRequest) GetTxCborOk() (*string, bool)`

GetTxCborOk returns a tuple with the TxCbor field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCbor

`func (o *ApiTxDecodeRequest) SetTxCbor(v string)`

SetTxCbor sets TxCbor field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# ApiTxIDRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**TxCbor** | **string** | raw hex CBOR or JSON text envelope |

## Methods

### NewApiTxIDRequest

`func NewApiTxIDRequest(txCbor string, ) *ApiTxIDRequest`

NewApiTxIDRequest instantiates a new ApiTxIDRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiTxIDRequestWithDefaults

`func NewApiTxIDRequestWithDefaults() *ApiTxIDRequest`

NewApiTxIDRequestWithDefaults instantiates a new ApiTxIDRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTxCbor

`func (o *ApiTxIDRequest) GetTxCbor() string`

GetTxCbor returns the TxCbor field if non-nil, zero value otherwise.

### GetTxCborOk

`func (o *ApiTxIDRequest) GetTxCborOk() (*string, bool)`

GetTxCborOk returns a tuple with the TxCbor field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCbor

`func (o *ApiTxIDRequest) SetTxCbor(v string)`

SetTxCbor sets TxCbor field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

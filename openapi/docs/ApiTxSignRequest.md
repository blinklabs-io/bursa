# ApiTxSignRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**SigningKeys** | **[]string** |  |
**TxCbor** | **string** | raw hex CBOR or JSON text envelope |

## Methods

### NewApiTxSignRequest

`func NewApiTxSignRequest(signingKeys []string, txCbor string) *ApiTxSignRequest`

NewApiTxSignRequest instantiates a new ApiTxSignRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiTxSignRequestWithDefaults

`func NewApiTxSignRequestWithDefaults() *ApiTxSignRequest`

NewApiTxSignRequestWithDefaults instantiates a new ApiTxSignRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSigningKeys

`func (o *ApiTxSignRequest) GetSigningKeys() []string`

GetSigningKeys returns the SigningKeys field if non-nil, zero value otherwise.

### GetSigningKeysOk

`func (o *ApiTxSignRequest) GetSigningKeysOk() ([]string, bool)`

GetSigningKeysOk returns a tuple with the SigningKeys field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSigningKeys

`func (o *ApiTxSignRequest) SetSigningKeys(v []string)`

SetSigningKeys sets SigningKeys field to given value.


### GetTxCbor

`func (o *ApiTxSignRequest) GetTxCbor() string`

GetTxCbor returns the TxCbor field if non-nil, zero value otherwise.

### GetTxCborOk

`func (o *ApiTxSignRequest) GetTxCborOk() (*string, bool)`

GetTxCborOk returns a tuple with the TxCbor field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCbor

`func (o *ApiTxSignRequest) SetTxCbor(v string)`

SetTxCbor sets TxCbor field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

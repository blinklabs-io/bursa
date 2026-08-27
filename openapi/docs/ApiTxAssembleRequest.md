# ApiTxAssembleRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**TxCbor** | **string** | raw hex CBOR or JSON text envelope |
**Witnesses** | **[]string** |  |

## Methods

### NewApiTxAssembleRequest

`func NewApiTxAssembleRequest(txCbor string, witnesses []string, ) *ApiTxAssembleRequest`

NewApiTxAssembleRequest instantiates a new ApiTxAssembleRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiTxAssembleRequestWithDefaults

`func NewApiTxAssembleRequestWithDefaults() *ApiTxAssembleRequest`

NewApiTxAssembleRequestWithDefaults instantiates a new ApiTxAssembleRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTxCbor

`func (o *ApiTxAssembleRequest) GetTxCbor() string`

GetTxCbor returns the TxCbor field if non-nil, zero value otherwise.

### GetTxCborOk

`func (o *ApiTxAssembleRequest) GetTxCborOk() (*string, bool)`

GetTxCborOk returns a tuple with the TxCbor field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCbor

`func (o *ApiTxAssembleRequest) SetTxCbor(v string)`

SetTxCbor sets TxCbor field to given value.


### GetWitnesses

`func (o *ApiTxAssembleRequest) GetWitnesses() []string`

GetWitnesses returns the Witnesses field if non-nil, zero value otherwise.

### GetWitnessesOk

`func (o *ApiTxAssembleRequest) GetWitnessesOk() (*[]string, bool)`

GetWitnessesOk returns a tuple with the Witnesses field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetWitnesses

`func (o *ApiTxAssembleRequest) SetWitnesses(v []string)`

SetWitnesses sets Witnesses field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

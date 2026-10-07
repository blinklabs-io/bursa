# BursaTxOutput

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Address** | Pointer to **string** |  | [optional]
**HasAssets** | Pointer to **bool** | HasAssets is true when the output carries native (multi-)assets in addition to lovelace. The policy engine treats native-asset movement as a distinct, deny-by-default operation because lovelace limits do not bound token quantities. | [optional]
**Lovelace** | Pointer to **string** |  | [optional]

## Methods

### NewBursaTxOutput

`func NewBursaTxOutput() *BursaTxOutput`

NewBursaTxOutput instantiates a new BursaTxOutput object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBursaTxOutputWithDefaults

`func NewBursaTxOutputWithDefaults() *BursaTxOutput`

NewBursaTxOutputWithDefaults instantiates a new BursaTxOutput object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAddress

`func (o *BursaTxOutput) GetAddress() string`

GetAddress returns the Address field if non-nil, zero value otherwise.

### GetAddressOk

`func (o *BursaTxOutput) GetAddressOk() (*string, bool)`

GetAddressOk returns a tuple with the Address field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddress

`func (o *BursaTxOutput) SetAddress(v string)`

SetAddress sets Address field to given value.

### HasAddress

`func (o *BursaTxOutput) HasAddress() bool`

HasAddress returns a boolean if a field has been set.

### GetHasAssets

`func (o *BursaTxOutput) GetHasAssets() bool`

GetHasAssets returns the HasAssets field if non-nil, zero value otherwise.

### GetHasAssetsOk

`func (o *BursaTxOutput) GetHasAssetsOk() (*bool, bool)`

GetHasAssetsOk returns a tuple with the HasAssets field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasAssets

`func (o *BursaTxOutput) SetHasAssets(v bool)`

SetHasAssets sets HasAssets field to given value.

### HasHasAssets

`func (o *BursaTxOutput) HasHasAssets() bool`

HasHasAssets returns a boolean if a field has been set.

### GetLovelace

`func (o *BursaTxOutput) GetLovelace() string`

GetLovelace returns the Lovelace field if non-nil, zero value otherwise.

### GetLovelaceOk

`func (o *BursaTxOutput) GetLovelaceOk() (*string, bool)`

GetLovelaceOk returns a tuple with the Lovelace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLovelace

`func (o *BursaTxOutput) SetLovelace(v string)`

SetLovelace sets Lovelace field to given value.

### HasLovelace

`func (o *BursaTxOutput) HasLovelace() bool`

HasLovelace returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# ApiAddressParseRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Address** | **string** |  | 
**Format** | Pointer to **string** | Format selects how Address is encoded: \&quot;text\&quot; (bech32 or base58, the default), \&quot;hex\&quot;, or \&quot;base64\&quot; for the raw address bytes. | [optional] 

## Methods

### NewApiAddressParseRequest

`func NewApiAddressParseRequest(address string, ) *ApiAddressParseRequest`

NewApiAddressParseRequest instantiates a new ApiAddressParseRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiAddressParseRequestWithDefaults

`func NewApiAddressParseRequestWithDefaults() *ApiAddressParseRequest`

NewApiAddressParseRequestWithDefaults instantiates a new ApiAddressParseRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAddress

`func (o *ApiAddressParseRequest) GetAddress() string`

GetAddress returns the Address field if non-nil, zero value otherwise.

### GetAddressOk

`func (o *ApiAddressParseRequest) GetAddressOk() (*string, bool)`

GetAddressOk returns a tuple with the Address field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddress

`func (o *ApiAddressParseRequest) SetAddress(v string)`

SetAddress sets Address field to given value.


### GetFormat

`func (o *ApiAddressParseRequest) GetFormat() string`

GetFormat returns the Format field if non-nil, zero value otherwise.

### GetFormatOk

`func (o *ApiAddressParseRequest) GetFormatOk() (*string, bool)`

GetFormatOk returns a tuple with the Format field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFormat

`func (o *ApiAddressParseRequest) SetFormat(v string)`

SetFormat sets Format field to given value.

### HasFormat

`func (o *ApiAddressParseRequest) HasFormat() bool`

HasFormat returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



# BursaTxInspection

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**CertificateCount** | Pointer to **int32** |  | [optional]
**Era** | Pointer to **string** |  | [optional]
**Fee** | Pointer to **string** |  | [optional]
**HasMetadata** | Pointer to **bool** |  | [optional]
**HasMint** | Pointer to **bool** |  | [optional]
**HasTreasuryDonation** | Pointer to **bool** |  | [optional]
**Inputs** | Pointer to [**[]BursaTxInput**](BursaTxInput.md) |  | [optional]
**IsValid** | Pointer to **bool** |  | [optional]
**NativeScripts** | Pointer to **int32** |  | [optional]
**Outputs** | Pointer to [**[]BursaTxOutput**](BursaTxOutput.md) |  | [optional]
**ProposalProcedureCount** | Pointer to **int32** |  | [optional]
**RequiredSigners** | Pointer to **int32** |  | [optional]
**SizeBytes** | Pointer to **int32** |  | [optional]
**Ttl** | Pointer to **int32** |  | [optional]
**TxId** | Pointer to **string** |  | [optional]
**ValidityIntervalStart** | Pointer to **int32** |  | [optional]
**VkeyWitnesses** | Pointer to **int32** |  | [optional]
**VotingProcedureCount** | Pointer to **int32** | Conway governance and treasury components. These authorize high-impact actions (casting DRep/committee votes, submitting governance proposals, donating to the treasury) that are independent of outputs/certificates/withdrawals, so the policy engine must inspect and gate them explicitly. | [optional]
**WithdrawalCount** | Pointer to **int32** |  | [optional]

## Methods

### NewBursaTxInspection

`func NewBursaTxInspection() *BursaTxInspection`

NewBursaTxInspection instantiates a new BursaTxInspection object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBursaTxInspectionWithDefaults

`func NewBursaTxInspectionWithDefaults() *BursaTxInspection`

NewBursaTxInspectionWithDefaults instantiates a new BursaTxInspection object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCertificateCount

`func (o *BursaTxInspection) GetCertificateCount() int32`

GetCertificateCount returns the CertificateCount field if non-nil, zero value otherwise.

### GetCertificateCountOk

`func (o *BursaTxInspection) GetCertificateCountOk() (*int32, bool)`

GetCertificateCountOk returns a tuple with the CertificateCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCertificateCount

`func (o *BursaTxInspection) SetCertificateCount(v int32)`

SetCertificateCount sets CertificateCount field to given value.

### HasCertificateCount

`func (o *BursaTxInspection) HasCertificateCount() bool`

HasCertificateCount returns a boolean if a field has been set.

### GetEra

`func (o *BursaTxInspection) GetEra() string`

GetEra returns the Era field if non-nil, zero value otherwise.

### GetEraOk

`func (o *BursaTxInspection) GetEraOk() (*string, bool)`

GetEraOk returns a tuple with the Era field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEra

`func (o *BursaTxInspection) SetEra(v string)`

SetEra sets Era field to given value.

### HasEra

`func (o *BursaTxInspection) HasEra() bool`

HasEra returns a boolean if a field has been set.

### GetFee

`func (o *BursaTxInspection) GetFee() string`

GetFee returns the Fee field if non-nil, zero value otherwise.

### GetFeeOk

`func (o *BursaTxInspection) GetFeeOk() (*string, bool)`

GetFeeOk returns a tuple with the Fee field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFee

`func (o *BursaTxInspection) SetFee(v string)`

SetFee sets Fee field to given value.

### HasFee

`func (o *BursaTxInspection) HasFee() bool`

HasFee returns a boolean if a field has been set.

### GetHasMetadata

`func (o *BursaTxInspection) GetHasMetadata() bool`

GetHasMetadata returns the HasMetadata field if non-nil, zero value otherwise.

### GetHasMetadataOk

`func (o *BursaTxInspection) GetHasMetadataOk() (*bool, bool)`

GetHasMetadataOk returns a tuple with the HasMetadata field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasMetadata

`func (o *BursaTxInspection) SetHasMetadata(v bool)`

SetHasMetadata sets HasMetadata field to given value.

### HasHasMetadata

`func (o *BursaTxInspection) HasHasMetadata() bool`

HasHasMetadata returns a boolean if a field has been set.

### GetHasMint

`func (o *BursaTxInspection) GetHasMint() bool`

GetHasMint returns the HasMint field if non-nil, zero value otherwise.

### GetHasMintOk

`func (o *BursaTxInspection) GetHasMintOk() (*bool, bool)`

GetHasMintOk returns a tuple with the HasMint field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasMint

`func (o *BursaTxInspection) SetHasMint(v bool)`

SetHasMint sets HasMint field to given value.

### HasHasMint

`func (o *BursaTxInspection) HasHasMint() bool`

HasHasMint returns a boolean if a field has been set.

### GetHasTreasuryDonation

`func (o *BursaTxInspection) GetHasTreasuryDonation() bool`

GetHasTreasuryDonation returns the HasTreasuryDonation field if non-nil, zero value otherwise.

### GetHasTreasuryDonationOk

`func (o *BursaTxInspection) GetHasTreasuryDonationOk() (*bool, bool)`

GetHasTreasuryDonationOk returns a tuple with the HasTreasuryDonation field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasTreasuryDonation

`func (o *BursaTxInspection) SetHasTreasuryDonation(v bool)`

SetHasTreasuryDonation sets HasTreasuryDonation field to given value.

### HasHasTreasuryDonation

`func (o *BursaTxInspection) HasHasTreasuryDonation() bool`

HasHasTreasuryDonation returns a boolean if a field has been set.

### GetInputs

`func (o *BursaTxInspection) GetInputs() []BursaTxInput`

GetInputs returns the Inputs field if non-nil, zero value otherwise.

### GetInputsOk

`func (o *BursaTxInspection) GetInputsOk() (*[]BursaTxInput, bool)`

GetInputsOk returns a tuple with the Inputs field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInputs

`func (o *BursaTxInspection) SetInputs(v []BursaTxInput)`

SetInputs sets Inputs field to given value.

### HasInputs

`func (o *BursaTxInspection) HasInputs() bool`

HasInputs returns a boolean if a field has been set.

### GetIsValid

`func (o *BursaTxInspection) GetIsValid() bool`

GetIsValid returns the IsValid field if non-nil, zero value otherwise.

### GetIsValidOk

`func (o *BursaTxInspection) GetIsValidOk() (*bool, bool)`

GetIsValidOk returns a tuple with the IsValid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsValid

`func (o *BursaTxInspection) SetIsValid(v bool)`

SetIsValid sets IsValid field to given value.

### HasIsValid

`func (o *BursaTxInspection) HasIsValid() bool`

HasIsValid returns a boolean if a field has been set.

### GetNativeScripts

`func (o *BursaTxInspection) GetNativeScripts() int32`

GetNativeScripts returns the NativeScripts field if non-nil, zero value otherwise.

### GetNativeScriptsOk

`func (o *BursaTxInspection) GetNativeScriptsOk() (*int32, bool)`

GetNativeScriptsOk returns a tuple with the NativeScripts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNativeScripts

`func (o *BursaTxInspection) SetNativeScripts(v int32)`

SetNativeScripts sets NativeScripts field to given value.

### HasNativeScripts

`func (o *BursaTxInspection) HasNativeScripts() bool`

HasNativeScripts returns a boolean if a field has been set.

### GetOutputs

`func (o *BursaTxInspection) GetOutputs() []BursaTxOutput`

GetOutputs returns the Outputs field if non-nil, zero value otherwise.

### GetOutputsOk

`func (o *BursaTxInspection) GetOutputsOk() (*[]BursaTxOutput, bool)`

GetOutputsOk returns a tuple with the Outputs field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOutputs

`func (o *BursaTxInspection) SetOutputs(v []BursaTxOutput)`

SetOutputs sets Outputs field to given value.

### HasOutputs

`func (o *BursaTxInspection) HasOutputs() bool`

HasOutputs returns a boolean if a field has been set.

### GetProposalProcedureCount

`func (o *BursaTxInspection) GetProposalProcedureCount() int32`

GetProposalProcedureCount returns the ProposalProcedureCount field if non-nil, zero value otherwise.

### GetProposalProcedureCountOk

`func (o *BursaTxInspection) GetProposalProcedureCountOk() (*int32, bool)`

GetProposalProcedureCountOk returns a tuple with the ProposalProcedureCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProposalProcedureCount

`func (o *BursaTxInspection) SetProposalProcedureCount(v int32)`

SetProposalProcedureCount sets ProposalProcedureCount field to given value.

### HasProposalProcedureCount

`func (o *BursaTxInspection) HasProposalProcedureCount() bool`

HasProposalProcedureCount returns a boolean if a field has been set.

### GetRequiredSigners

`func (o *BursaTxInspection) GetRequiredSigners() int32`

GetRequiredSigners returns the RequiredSigners field if non-nil, zero value otherwise.

### GetRequiredSignersOk

`func (o *BursaTxInspection) GetRequiredSignersOk() (*int32, bool)`

GetRequiredSignersOk returns a tuple with the RequiredSigners field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequiredSigners

`func (o *BursaTxInspection) SetRequiredSigners(v int32)`

SetRequiredSigners sets RequiredSigners field to given value.

### HasRequiredSigners

`func (o *BursaTxInspection) HasRequiredSigners() bool`

HasRequiredSigners returns a boolean if a field has been set.

### GetSizeBytes

`func (o *BursaTxInspection) GetSizeBytes() int32`

GetSizeBytes returns the SizeBytes field if non-nil, zero value otherwise.

### GetSizeBytesOk

`func (o *BursaTxInspection) GetSizeBytesOk() (*int32, bool)`

GetSizeBytesOk returns a tuple with the SizeBytes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSizeBytes

`func (o *BursaTxInspection) SetSizeBytes(v int32)`

SetSizeBytes sets SizeBytes field to given value.

### HasSizeBytes

`func (o *BursaTxInspection) HasSizeBytes() bool`

HasSizeBytes returns a boolean if a field has been set.

### GetTtl

`func (o *BursaTxInspection) GetTtl() int32`

GetTtl returns the Ttl field if non-nil, zero value otherwise.

### GetTtlOk

`func (o *BursaTxInspection) GetTtlOk() (*int32, bool)`

GetTtlOk returns a tuple with the Ttl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTtl

`func (o *BursaTxInspection) SetTtl(v int32)`

SetTtl sets Ttl field to given value.

### HasTtl

`func (o *BursaTxInspection) HasTtl() bool`

HasTtl returns a boolean if a field has been set.

### GetTxId

`func (o *BursaTxInspection) GetTxId() string`

GetTxId returns the TxId field if non-nil, zero value otherwise.

### GetTxIdOk

`func (o *BursaTxInspection) GetTxIdOk() (*string, bool)`

GetTxIdOk returns a tuple with the TxId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxId

`func (o *BursaTxInspection) SetTxId(v string)`

SetTxId sets TxId field to given value.

### HasTxId

`func (o *BursaTxInspection) HasTxId() bool`

HasTxId returns a boolean if a field has been set.

### GetValidityIntervalStart

`func (o *BursaTxInspection) GetValidityIntervalStart() int32`

GetValidityIntervalStart returns the ValidityIntervalStart field if non-nil, zero value otherwise.

### GetValidityIntervalStartOk

`func (o *BursaTxInspection) GetValidityIntervalStartOk() (*int32, bool)`

GetValidityIntervalStartOk returns a tuple with the ValidityIntervalStart field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetValidityIntervalStart

`func (o *BursaTxInspection) SetValidityIntervalStart(v int32)`

SetValidityIntervalStart sets ValidityIntervalStart field to given value.

### HasValidityIntervalStart

`func (o *BursaTxInspection) HasValidityIntervalStart() bool`

HasValidityIntervalStart returns a boolean if a field has been set.

### GetVkeyWitnesses

`func (o *BursaTxInspection) GetVkeyWitnesses() int32`

GetVkeyWitnesses returns the VkeyWitnesses field if non-nil, zero value otherwise.

### GetVkeyWitnessesOk

`func (o *BursaTxInspection) GetVkeyWitnessesOk() (*int32, bool)`

GetVkeyWitnessesOk returns a tuple with the VkeyWitnesses field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVkeyWitnesses

`func (o *BursaTxInspection) SetVkeyWitnesses(v int32)`

SetVkeyWitnesses sets VkeyWitnesses field to given value.

### HasVkeyWitnesses

`func (o *BursaTxInspection) HasVkeyWitnesses() bool`

HasVkeyWitnesses returns a boolean if a field has been set.

### GetVotingProcedureCount

`func (o *BursaTxInspection) GetVotingProcedureCount() int32`

GetVotingProcedureCount returns the VotingProcedureCount field if non-nil, zero value otherwise.

### GetVotingProcedureCountOk

`func (o *BursaTxInspection) GetVotingProcedureCountOk() (*int32, bool)`

GetVotingProcedureCountOk returns a tuple with the VotingProcedureCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVotingProcedureCount

`func (o *BursaTxInspection) SetVotingProcedureCount(v int32)`

SetVotingProcedureCount sets VotingProcedureCount field to given value.

### HasVotingProcedureCount

`func (o *BursaTxInspection) HasVotingProcedureCount() bool`

HasVotingProcedureCount returns a boolean if a field has been set.

### GetWithdrawalCount

`func (o *BursaTxInspection) GetWithdrawalCount() int32`

GetWithdrawalCount returns the WithdrawalCount field if non-nil, zero value otherwise.

### GetWithdrawalCountOk

`func (o *BursaTxInspection) GetWithdrawalCountOk() (*int32, bool)`

GetWithdrawalCountOk returns a tuple with the WithdrawalCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetWithdrawalCount

`func (o *BursaTxInspection) SetWithdrawalCount(v int32)`

SetWithdrawalCount sets WithdrawalCount field to given value.

### HasWithdrawalCount

`func (o *BursaTxInspection) HasWithdrawalCount() bool`

HasWithdrawalCount returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

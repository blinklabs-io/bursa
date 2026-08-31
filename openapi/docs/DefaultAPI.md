# \DefaultAPI

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ApiAddressBuildPost**](DefaultAPI.md#ApiAddressBuildPost) | **Post** /api/address/build | Build Cardano address
[**ApiAddressEnumeratePost**](DefaultAPI.md#ApiAddressEnumeratePost) | **Post** /api/address/enumerate | Enumerate derived addresses for a wallet
[**ApiAddressParsePost**](DefaultAPI.md#ApiAddressParsePost) | **Post** /api/address/parse | Parse Cardano address
[**ApiScriptAddressPost**](DefaultAPI.md#ApiScriptAddressPost) | **Post** /api/script/address | Generate script address
[**ApiScriptCreatePost**](DefaultAPI.md#ApiScriptCreatePost) | **Post** /api/script/create | Create a multi-signature script
[**ApiScriptValidatePost**](DefaultAPI.md#ApiScriptValidatePost) | **Post** /api/script/validate | Validate a script
[**ApiSignDataPost**](DefaultAPI.md#ApiSignDataPost) | **Post** /api/sign/data | Sign a message (CIP-8/CIP-30 signData)
[**ApiSignVerifyPost**](DefaultAPI.md#ApiSignVerifyPost) | **Post** /api/sign/verify | Verify a CIP-8/CIP-30 signData signature
[**ApiTxAssemblePost**](DefaultAPI.md#ApiTxAssemblePost) | **Post** /api/tx/assemble | Assemble a signed transaction
[**ApiTxDecodePost**](DefaultAPI.md#ApiTxDecodePost) | **Post** /api/tx/decode | Decode a transaction
[**ApiTxIdPost**](DefaultAPI.md#ApiTxIdPost) | **Post** /api/tx/id | Get a transaction id
[**ApiTxSignPost**](DefaultAPI.md#ApiTxSignPost) | **Post** /api/tx/sign | Sign a transaction
[**ApiTxWitnessPost**](DefaultAPI.md#ApiTxWitnessPost) | **Post** /api/tx/witness | Produce a transaction witness
[**ApiWalletCreatePost**](DefaultAPI.md#ApiWalletCreatePost) | **Post** /api/wallet/create | Create a wallet
[**ApiWalletDeletePost**](DefaultAPI.md#ApiWalletDeletePost) | **Post** /api/wallet/delete | Delete wallet from persistent storage
[**ApiWalletGetPost**](DefaultAPI.md#ApiWalletGetPost) | **Post** /api/wallet/get | Get wallet from persistent storage
[**ApiWalletListGet**](DefaultAPI.md#ApiWalletListGet) | **Get** /api/wallet/list | Lists wallets
[**ApiWalletRestorePost**](DefaultAPI.md#ApiWalletRestorePost) | **Post** /api/wallet/restore | Restore a wallet using a mnemonic seed phrase
[**ApiWalletUpdatePost**](DefaultAPI.md#ApiWalletUpdatePost) | **Post** /api/wallet/update | Update a wallet in persistent storage



## ApiAddressBuildPost

> ApiAddressBuildResponse ApiAddressBuildPost(ctx).Request(request).Execute()

Build Cardano address



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiAddressBuildRequest("Network_example") // ApiAddressBuildRequest | Address Build Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiAddressBuildPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiAddressBuildPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiAddressBuildPost`: ApiAddressBuildResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiAddressBuildPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiAddressBuildPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiAddressBuildRequest**](ApiAddressBuildRequest.md) | Address Build Request |

### Return type

[**ApiAddressBuildResponse**](ApiAddressBuildResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiAddressEnumeratePost

> []BursaEnumeratedAddress ApiAddressEnumeratePost(ctx).Request(request).Execute()

Enumerate derived addresses for a wallet



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiAddressEnumerateRequest(int32(123), "Mnemonic_example", "Network_example") // ApiAddressEnumerateRequest | Address Enumerate Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiAddressEnumeratePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiAddressEnumeratePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiAddressEnumeratePost`: []BursaEnumeratedAddress
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiAddressEnumeratePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiAddressEnumeratePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiAddressEnumerateRequest**](ApiAddressEnumerateRequest.md) | Address Enumerate Request |

### Return type

[**[]BursaEnumeratedAddress**](BursaEnumeratedAddress.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiAddressParsePost

> ApiAddressParseResponse ApiAddressParsePost(ctx).Request(request).Execute()

Parse Cardano address



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiAddressParseRequest("Address_example") // ApiAddressParseRequest | Address Parse Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiAddressParsePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiAddressParsePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiAddressParsePost`: ApiAddressParseResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiAddressParsePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiAddressParsePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiAddressParseRequest**](ApiAddressParseRequest.md) | Address Parse Request |

### Return type

[**ApiAddressParseResponse**](ApiAddressParseResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiScriptAddressPost

> ApiScriptAddressResponse ApiScriptAddressPost(ctx).Request(request).Execute()

Generate script address



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiScriptAddressRequest("Network_example", map[string]map[string]interface{}{"key": map[string]interface{}(123)}) // ApiScriptAddressRequest | Script Address Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiScriptAddressPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiScriptAddressPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiScriptAddressPost`: ApiScriptAddressResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiScriptAddressPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiScriptAddressPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiScriptAddressRequest**](ApiScriptAddressRequest.md) | Script Address Request |

### Return type

[**ApiScriptAddressResponse**](ApiScriptAddressResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiScriptCreatePost

> ApiScriptResponse ApiScriptCreatePost(ctx).Request(request).Execute()

Create a multi-signature script



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiScriptCreateRequest([]string{"KeyHashes_example"}, "Network_example", "Type_example") // ApiScriptCreateRequest | Script Create Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiScriptCreatePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiScriptCreatePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiScriptCreatePost`: ApiScriptResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiScriptCreatePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiScriptCreatePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiScriptCreateRequest**](ApiScriptCreateRequest.md) | Script Create Request |

### Return type

[**ApiScriptResponse**](ApiScriptResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiScriptValidatePost

> ApiScriptValidateResponse ApiScriptValidatePost(ctx).Request(request).Execute()

Validate a script



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiScriptValidateRequest(map[string]map[string]interface{}{"key": map[string]interface{}(123)}) // ApiScriptValidateRequest | Script Validate Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiScriptValidatePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiScriptValidatePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiScriptValidatePost`: ApiScriptValidateResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiScriptValidatePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiScriptValidatePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiScriptValidateRequest**](ApiScriptValidateRequest.md) | Script Validate Request |

### Return type

[**ApiScriptValidateResponse**](ApiScriptValidateResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiSignDataPost

> ApiSignDataResponse ApiSignDataPost(ctx).Request(request).Execute()

Sign a message (CIP-8/CIP-30 signData)



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiSignDataRequest("Address_example", "Payload_example", "SigningKey_example") // ApiSignDataRequest | Sign Data Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiSignDataPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiSignDataPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiSignDataPost`: ApiSignDataResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiSignDataPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiSignDataPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiSignDataRequest**](ApiSignDataRequest.md) | Sign Data Request |

### Return type

[**ApiSignDataResponse**](ApiSignDataResponse.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiSignVerifyPost

> ApiVerifyDataResponse ApiSignVerifyPost(ctx).Request(request).Execute()

Verify a CIP-8/CIP-30 signData signature



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiVerifyDataRequest("Key_example", "Payload_example", "Signature_example") // ApiVerifyDataRequest | Verify Data Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiSignVerifyPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiSignVerifyPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiSignVerifyPost`: ApiVerifyDataResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiSignVerifyPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiSignVerifyPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiVerifyDataRequest**](ApiVerifyDataRequest.md) | Verify Data Request |

### Return type

[**ApiVerifyDataResponse**](ApiVerifyDataResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiTxAssemblePost

> ApiTxCborResponse ApiTxAssemblePost(ctx).Request(request).Execute()

Assemble a signed transaction



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiTxAssembleRequest("TxCbor_example", []string{"Witnesses_example"}) // ApiTxAssembleRequest | Transaction + witnesses

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiTxAssemblePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiTxAssemblePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiTxAssemblePost`: ApiTxCborResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiTxAssemblePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiTxAssemblePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiTxAssembleRequest**](ApiTxAssembleRequest.md) | Transaction + witnesses |

### Return type

[**ApiTxCborResponse**](ApiTxCborResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiTxDecodePost

> BursaTxInspection ApiTxDecodePost(ctx).Request(request).Execute()

Decode a transaction



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiTxDecodeRequest("TxCbor_example") // ApiTxDecodeRequest | Transaction

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiTxDecodePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiTxDecodePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiTxDecodePost`: BursaTxInspection
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiTxDecodePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiTxDecodePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiTxDecodeRequest**](ApiTxDecodeRequest.md) | Transaction |

### Return type

[**BursaTxInspection**](BursaTxInspection.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiTxIdPost

> ApiTxIDResponse ApiTxIdPost(ctx).Request(request).Execute()

Get a transaction id



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiTxIDRequest("TxCbor_example") // ApiTxIDRequest | Transaction

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiTxIdPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiTxIdPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiTxIdPost`: ApiTxIDResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiTxIdPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiTxIdPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiTxIDRequest**](ApiTxIDRequest.md) | Transaction |

### Return type

[**ApiTxIDResponse**](ApiTxIDResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiTxSignPost

> ApiTxCborResponse ApiTxSignPost(ctx).Request(request).Execute()

Sign a transaction



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiTxSignRequest([]string{"SigningKeys_example"}, "TxCbor_example") // ApiTxSignRequest | Transaction + signing keys

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiTxSignPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiTxSignPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiTxSignPost`: ApiTxCborResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiTxSignPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiTxSignPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiTxSignRequest**](ApiTxSignRequest.md) | Transaction + signing keys |

### Return type

[**ApiTxCborResponse**](ApiTxCborResponse.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiTxWitnessPost

> ApiTxWitnessResponse ApiTxWitnessPost(ctx).Request(request).Execute()

Produce a transaction witness



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiTxWitnessRequest("SigningKey_example", "TxCbor_example") // ApiTxWitnessRequest | Transaction + signing key

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiTxWitnessPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiTxWitnessPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiTxWitnessPost`: ApiTxWitnessResponse
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiTxWitnessPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiTxWitnessPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiTxWitnessRequest**](ApiTxWitnessRequest.md) | Transaction + signing key |

### Return type

[**ApiTxWitnessResponse**](ApiTxWitnessResponse.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiWalletCreatePost

> BursaWallet ApiWalletCreatePost(ctx).Execute()

Create a wallet



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletCreatePost(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletCreatePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletCreatePost`: BursaWallet
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletCreatePost`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletCreatePostRequest struct via the builder pattern


### Return type

[**BursaWallet**](BursaWallet.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiWalletDeletePost

> string ApiWalletDeletePost(ctx).Request(request).Execute()

Delete wallet from persistent storage



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiWalletDeleteRequest("Name_example") // ApiWalletDeleteRequest | Wallet Delete Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletDeletePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletDeletePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletDeletePost`: string
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletDeletePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletDeletePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiWalletDeleteRequest**](ApiWalletDeleteRequest.md) | Wallet Delete Request |

### Return type

**string**

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiWalletGetPost

> BursaWallet ApiWalletGetPost(ctx).Request(request).Execute()

Get wallet from persistent storage



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiWalletGetRequest("Name_example") // ApiWalletGetRequest | Wallet Restore Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletGetPost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletGetPost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletGetPost`: BursaWallet
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletGetPost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletGetPostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiWalletGetRequest**](ApiWalletGetRequest.md) | Wallet Restore Request |

### Return type

[**BursaWallet**](BursaWallet.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiWalletListGet

> []string ApiWalletListGet(ctx).Execute()

Lists wallets



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletListGet(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletListGet``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletListGet`: []string
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletListGet`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletListGetRequest struct via the builder pattern


### Return type

**[]string**

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiWalletRestorePost

> BursaWallet ApiWalletRestorePost(ctx).Request(request).Execute()

Restore a wallet using a mnemonic seed phrase



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiWalletRestoreRequest("Mnemonic_example") // ApiWalletRestoreRequest | Wallet Restore Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletRestorePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletRestorePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletRestorePost`: BursaWallet
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletRestorePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletRestorePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiWalletRestoreRequest**](ApiWalletRestoreRequest.md) | Wallet Restore Request |

### Return type

[**BursaWallet**](BursaWallet.md)

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ApiWalletUpdatePost

> string ApiWalletUpdatePost(ctx).Request(request).Execute()

Update a wallet in persistent storage



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/bursa/openapi"
)

func main() {
	request := *openapiclient.NewApiWalletUpdateRequest("Name_example") // ApiWalletUpdateRequest | Wallet Update Request

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletUpdatePost(context.Background()).Request(request).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletUpdatePost``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletUpdatePost`: string
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletUpdatePost`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletUpdatePostRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**ApiWalletUpdateRequest**](ApiWalletUpdateRequest.md) | Wallet Update Request |

### Return type

**string**

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

# \DefaultAPI

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ApiWalletCreateGet**](DefaultAPI.md#ApiWalletCreateGet) | **Get** /api/wallet/create | Create a wallet
[**ApiWalletDeletePost**](DefaultAPI.md#ApiWalletDeletePost) | **Post** /api/wallet/delete | Delete wallet from persistent storage
[**ApiWalletGetPost**](DefaultAPI.md#ApiWalletGetPost) | **Post** /api/wallet/get | Get wallet from persistent storage
[**ApiWalletListGet**](DefaultAPI.md#ApiWalletListGet) | **Get** /api/wallet/list | Lists wallets
[**ApiWalletRestorePost**](DefaultAPI.md#ApiWalletRestorePost) | **Post** /api/wallet/restore | Restore a wallet using a mnemonic seed phrase
[**ApiWalletUpdatePost**](DefaultAPI.md#ApiWalletUpdatePost) | **Post** /api/wallet/update | Update a wallet in persistent storage



## ApiWalletCreateGet

> BursaWallet ApiWalletCreateGet(ctx).Execute()

Create a wallet



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/blinklabs-io/cardano-node-api/openapi"
)

func main() {

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DefaultAPI.ApiWalletCreateGet(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DefaultAPI.ApiWalletCreateGet``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ApiWalletCreateGet`: BursaWallet
	fmt.Fprintf(os.Stdout, "Response from `DefaultAPI.ApiWalletCreateGet`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiApiWalletCreateGetRequest struct via the builder pattern


### Return type

[**BursaWallet**](BursaWallet.md)

### Authorization

No authorization required

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
	openapiclient "github.com/blinklabs-io/cardano-node-api/openapi"
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

No authorization required

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
	openapiclient "github.com/blinklabs-io/cardano-node-api/openapi"
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

No authorization required

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
	openapiclient "github.com/blinklabs-io/cardano-node-api/openapi"
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

No authorization required

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
	openapiclient "github.com/blinklabs-io/cardano-node-api/openapi"
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

No authorization required

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
	openapiclient "github.com/blinklabs-io/cardano-node-api/openapi"
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

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Blink Labs",
            "url": "https://blinklabs.io",
            "email": "support@blinklabs.io"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/wallet/create": {
            "get": {
                "description": "Create a wallet and return details",
                "produces": [
                    "application/json"
                ],
                "summary": "CreateWallet",
                "responses": {
                    "200": {
                        "description": "Ok",
                        "schema": {
                            "$ref": "#/definitions/bursa.Wallet"
                        }
                    }
                }
            }
        },
        "/api/wallet/restore": {
            "post": {
                "description": "Restores a wallet using the provided mnemonic seed phrase and returns wallet details.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Restore a wallet using a mnemonic seed phrase",
                "parameters": [
                    {
                        "description": "Wallet Restore Request",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.WalletRestoreRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Wallet successfully restored",
                        "schema": {
                            "$ref": "#/definitions/bursa.Wallet"
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "api.WalletRestoreRequest": {
            "type": "object",
            "required": [
                "mnemonic"
            ],
            "properties": {
                "mnemonic": {
                    "type": "string"
                }
            }
        },
        "bursa.KeyFile": {
            "type": "object",
            "properties": {
                "cborHex": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                }
            }
        },
        "bursa.Wallet": {
            "type": "object",
            "properties": {
                "mnemonic": {
                    "type": "string"
                },
                "payment_address": {
                    "type": "string"
                },
                "payment_kvey": {
                    "$ref": "#/definitions/bursa.KeyFile"
                },
                "payment_skey": {
                    "$ref": "#/definitions/bursa.KeyFile"
                },
                "stake_address": {
                    "type": "string"
                },
                "stake_skey": {
                    "$ref": "#/definitions/bursa.KeyFile"
                },
                "stake_vkey": {
                    "$ref": "#/definitions/bursa.KeyFile"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "v0",
	Host:             "",
	BasePath:         "/",
	Schemes:          []string{"http"},
	Title:            "bursa",
	Description:      "Programmable Cardano Wallet API",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
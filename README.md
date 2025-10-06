# bursa

<div align="center">
    <img src="./.github/assets/bursa-logo-with-text-horizontal.png" alt="Bursa Logo" width="640">
</div>

Programmatic Cardano Wallet

Start a Bursa wallet and interact with it using the Bursa API.

```golang
# Clone the Bursa repository
git clone git@github.com:blinklabs-io/bursa.git
cd bursa

# Start the Bursa API server
go run ./cmd/bursa api 
```

Access API Swagger documentation: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

For more information about Bursa CLI

```bash
go run ./cmd/bursa    
Usage:
  bursa [command]

Available Commands:
  api         Runs the api
  help        Help about any command
  wallet      Wallet commands

Flags:
  -h, --help   help for bursa

Use "bursa [command] --help" for more information about a command.
```

// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/blinklabs-io/bursa/internal/txbuilder"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

type (
	queryPoolRunner  func(ctx context.Context, socketPath, network string, poolID lcommon.PoolId) (*txbuilder.PoolQueryResult, error)
	queryStakeRunner func(ctx context.Context, socketPath, network, address string) (*txbuilder.StakeAddressQueryResult, error)
	queryUtxoRunner  func(ctx context.Context, socketPath, network, address string) ([]txbuilder.UTxOQueryResult, error)
	queryTipRunner   func(ctx context.Context, socketPath, network string) (*txbuilder.TipQueryResult, error)
)

func defaultQueryPool(ctx context.Context, socketPath, network string, poolID lcommon.PoolId) (*txbuilder.PoolQueryResult, error) {
	chain := txbuilder.NewN2C(socketPath, network)
	if err := chain.Open(ctx); err != nil {
		return nil, err
	}
	defer chain.Close()
	return chain.QueryPool(ctx, poolID, network)
}

func defaultQueryStake(ctx context.Context, socketPath, network, address string) (*txbuilder.StakeAddressQueryResult, error) {
	chain := txbuilder.NewN2C(socketPath, network)
	if err := chain.Open(ctx); err != nil {
		return nil, err
	}
	defer chain.Close()
	return chain.QueryStakeAddress(ctx, address, network)
}

func defaultQueryUtxo(ctx context.Context, socketPath, network, address string) ([]txbuilder.UTxOQueryResult, error) {
	chain := txbuilder.NewN2C(socketPath, network)
	if err := chain.Open(ctx); err != nil {
		return nil, err
	}
	defer chain.Close()
	return chain.QueryUTxOs(ctx, address)
}

func defaultQueryTip(ctx context.Context, socketPath, network string) (*txbuilder.TipQueryResult, error) {
	chain := txbuilder.NewN2C(socketPath, network)
	if err := chain.Open(ctx); err != nil {
		return nil, err
	}
	defer chain.Close()
	return chain.QueryTip(ctx)
}

// queryContext bounds a query command by --timeout, which must be positive.
func queryContext(timeoutSeconds int64) (context.Context, context.CancelFunc, error) {
	if timeoutSeconds <= 0 {
		return nil, nil, fmt.Errorf("--timeout must be positive, got %d", timeoutSeconds)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutSeconds)*time.Second,
	)
	return ctx, cancel, nil
}

func writeJSONOutput(data interface{}, outFile string) error {
	enc, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Println(string(enc))
		return nil
	}
	return os.WriteFile(outFile, enc, 0o600)
}

func RunQueryPool(socketPath, network, poolID, outFile string, timeoutSeconds int64) error {
	return runQueryPool(socketPath, network, poolID, outFile, timeoutSeconds, defaultQueryPool)
}

func runQueryPool(socketPath, network, poolID, outFile string, timeoutSeconds int64, runner queryPoolRunner) error {
	if socketPath == "" {
		return errors.New("--socket-path required")
	}
	if network == "" {
		return errors.New("--network required")
	}
	if poolID == "" {
		return errors.New("--pool-id required")
	}
	// Parse the pool id before dialing; parsing lives with the other pool
	// id parsing in cert.go.
	keyHash, err := parsePoolID(poolID)
	if err != nil {
		return fmt.Errorf("--pool-id: %w", err)
	}
	var poolId lcommon.PoolId
	copy(poolId[:], keyHash)

	ctx, cancel, err := queryContext(timeoutSeconds)
	if err != nil {
		return err
	}
	defer cancel()

	res, err := runner(ctx, socketPath, network, poolId)
	if err != nil {
		return err
	}
	return writeJSONOutput(res, outFile)
}

func RunQueryStakeAddress(socketPath, network, address, outFile string, timeoutSeconds int64) error {
	return runQueryStakeAddress(socketPath, network, address, outFile, timeoutSeconds, defaultQueryStake)
}

func runQueryStakeAddress(socketPath, network, address, outFile string, timeoutSeconds int64, runner queryStakeRunner) error {
	if socketPath == "" {
		return errors.New("--socket-path required")
	}
	if network == "" {
		return errors.New("--network required")
	}
	if address == "" {
		return errors.New("--address required")
	}
	// Only a reward (stake) address on the --network answers the right
	// query; validate before dialing.
	if _, err := txbuilder.ParseRewardAddress(address, network); err != nil {
		return fmt.Errorf("--address: %w", err)
	}

	ctx, cancel, err := queryContext(timeoutSeconds)
	if err != nil {
		return err
	}
	defer cancel()

	res, err := runner(ctx, socketPath, network, address)
	if err != nil {
		return err
	}
	return writeJSONOutput(res, outFile)
}

func RunQueryUtxo(socketPath, network, address, outFile string, timeoutSeconds int64) error {
	return runQueryUtxo(socketPath, network, address, outFile, timeoutSeconds, defaultQueryUtxo)
}

func runQueryUtxo(socketPath, network, address, outFile string, timeoutSeconds int64, runner queryUtxoRunner) error {
	if socketPath == "" {
		return errors.New("--socket-path required")
	}
	if network == "" {
		return errors.New("--network required")
	}
	if address == "" {
		return errors.New("--address required")
	}
	// Only a payment address on the --network holds UTxOs; validate before
	// dialing.
	if _, err := txbuilder.ParsePaymentAddress(address, network); err != nil {
		return fmt.Errorf("--address: %w", err)
	}

	ctx, cancel, err := queryContext(timeoutSeconds)
	if err != nil {
		return err
	}
	defer cancel()

	res, err := runner(ctx, socketPath, network, address)
	if err != nil {
		return err
	}
	return writeJSONOutput(res, outFile)
}

func RunQueryTip(socketPath, network, outFile string, timeoutSeconds int64) error {
	return runQueryTip(socketPath, network, outFile, timeoutSeconds, defaultQueryTip)
}

func runQueryTip(socketPath, network, outFile string, timeoutSeconds int64, runner queryTipRunner) error {
	if socketPath == "" {
		return errors.New("--socket-path required")
	}
	if network == "" {
		return errors.New("--network required")
	}

	ctx, cancel, err := queryContext(timeoutSeconds)
	if err != nil {
		return err
	}
	defer cancel()

	res, err := runner(ctx, socketPath, network)
	if err != nil {
		return err
	}
	return writeJSONOutput(res, outFile)
}

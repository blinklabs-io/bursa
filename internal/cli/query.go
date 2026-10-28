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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa/internal/txbuilder"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

type queryPoolRunner func(ctx context.Context, socketPath, network, poolID string) (*txbuilder.PoolQueryResult, error)
type queryStakeRunner func(ctx context.Context, socketPath, network, address string) (*txbuilder.StakeAddressQueryResult, error)
type queryUtxoRunner func(ctx context.Context, socketPath, network, address string) ([]txbuilder.UTxOQueryResult, error)
type queryTipRunner func(ctx context.Context, socketPath, network string) (*txbuilder.TipQueryResult, error)

func defaultQueryPool(ctx context.Context, socketPath, network, poolID string) (*txbuilder.PoolQueryResult, error) {
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
	return chain.QueryStakeAddress(ctx, address)
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
	// Validate pool id
	if len(poolID) == 56 {
		if _, err := hex.DecodeString(poolID); err != nil {
			return fmt.Errorf("bad pool id: %w", err)
		}
	} else if len(poolID) > 5 && poolID[:5] == "pool1" {
		if _, err := lcommon.NewPoolIdFromBech32(poolID); err != nil {
			return fmt.Errorf("bad pool id: %w", err)
		}
	} else {
		return errors.New("bad pool id")
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	} else {
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

	res, err := runner(ctx, socketPath, network, poolID)
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
	// Validate stake address
	if !(strings.HasPrefix(address, "stake1") || strings.HasPrefix(address, "stake_test1")) {
		// Try to parse
		if _, err := lcommon.NewAddress(address); err != nil {
			return fmt.Errorf("bad address: %w", err)
		}
	} else {
		if _, err := lcommon.NewAddress(address); err != nil {
			return fmt.Errorf("bad address: %w", err)
		}
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	} else {
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

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
	if _, err := lcommon.NewAddress(address); err != nil {
		return fmt.Errorf("bad address: %w", err)
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	} else {
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

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

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	} else {
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

	res, err := runner(ctx, socketPath, network)
	if err != nil {
		return err
	}
	return writeJSONOutput(res, outFile)
}

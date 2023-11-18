package vm

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	suave "github.com/ethereum/go-ethereum/suave/core"
)

var (
	confStorePrecompileStoreMeter    = metrics.NewRegisteredMeter("suave/confstore/store", nil)
	confStorePrecompileRetrieveMeter = metrics.NewRegisteredMeter("suave/confstore/retrieve", nil)
)

var (
	isConfidentialAddress = common.HexToAddress("0x42010000")
)

/* General utility precompiles */

func (b *suaveRuntime) confidentialInputs() ([]byte, error) {
	return b.suaveContext.ConfidentialInputs, nil
}

/* Confidential store precompiles */

func (b *suaveRuntime) confidentialStore(bidId types.BidId, key string, data []byte) error {
	bid, err := b.suaveContext.Backend.ConfidentialStore.FetchBidById(bidId)
	if err != nil {
		return suave.ErrBidNotFound
	}

	log.Info("confStore", "bidId", bidId, "key", key)

	caller, err := checkIsPrecompileCallAllowed(b.suaveContext, confidentialStoreAddr, bid)
	if err != nil {
		return err
	}

	if metrics.Enabled {
		confStorePrecompileStoreMeter.Mark(int64(len(data)))
	}

	_, err = b.suaveContext.Backend.ConfidentialStore.Store(bidId, caller, key, data)
	if err != nil {
		return err
	}

	return nil
}

func (b *suaveRuntime) confidentialRetrieve(bidId types.BidId, key string) ([]byte, error) {
	bid, err := b.suaveContext.Backend.ConfidentialStore.FetchBidById(bidId)
	if err != nil {
		return nil, suave.ErrBidNotFound
	}

	caller, err := checkIsPrecompileCallAllowed(b.suaveContext, confidentialRetrieveAddr, bid)
	if err != nil {
		return nil, err
	}

	data, err := b.suaveContext.Backend.ConfidentialStore.Retrieve(bidId, caller, key)
	if err != nil {
		return []byte(err.Error()), err
	}

	if metrics.Enabled {
		confStorePrecompileRetrieveMeter.Mark(int64(len(data)))
	}

	return data, nil
}

/* Bid precompiles */

func (b *suaveRuntime) newBid(decryptionCondition uint64, allowedPeekers []common.Address, allowedStores []common.Address, BidType string) (types.Bid, error) {
	if b.suaveContext.ConfidentialComputeRequestTx == nil {
		panic("newBid: source transaction not present")
	}

	bid, err := b.suaveContext.Backend.ConfidentialStore.InitializeBid(types.Bid{
		Salt:                suave.RandomBidId(),
		DecryptionCondition: decryptionCondition,
		AllowedPeekers:      allowedPeekers,
		AllowedStores:       allowedStores,
		Version:             BidType, // TODO : make generic
	})
	if err != nil {
		return types.Bid{}, err
	}

	return bid, nil
}

func (b *suaveRuntime) fetchBids(targetBlock uint64, namespace string) ([]types.Bid, error) {
	bids1 := b.suaveContext.Backend.ConfidentialStore.FetchBidsByProtocolAndBlock(targetBlock, namespace)

	bids := make([]types.Bid, 0, len(bids1))
	for _, bid := range bids1 {
		bids = append(bids, bid.ToInnerBid())
	}

	return bids, nil
}

/* Blob merging precompiles */
func (b *suaveRuntime) mergeBlobData(toAddresses []common.Address, blobsData [][]byte) ([][]byte, error) {
	if len(toAddresses) != len(blobsData) {
		return nil, fmt.Errorf("toAddresses and blobsData parameter should have the same length")
	}

	for _, toAddress := range toAddresses {
		if len(toAddress) != 42 {
			return nil, fmt.Errorf("To address must have 42 length.")
		} else if toAddress.Hex() == "0x0000000000000000000000000000000000000000" {
			return nil, fmt.Errorf("To address can't be null in the blob tx.")
		}
	}

	const MAX_BLOB_SIZE_IN_BYTES = 1024 * 128 // 131072
	for _, blobData := range blobsData {
		if len(blobData) > MAX_BLOB_SIZE_IN_BYTES {
			return nil, fmt.Errorf("One of the blob data is longer than max allowed length of %d bytes", MAX_BLOB_SIZE_IN_BYTES)
		}
	}

	// Sort blobsData by length in descending order
	sort.Slice(blobsData, func(i, j int) bool {
		return len(blobsData[i]) > len(blobsData[j])
	})

	var result [][]byte
	const (
		ADDRESS_SIZE          = 42
		BLOB_DATA_LENGTH_SIZE = 3
	)
	for len(blobsData) > 0 {
		var mergedBlobSize int = 0
		var mergedBlobData []byte
		var removedBlobs [][]byte

		for i, iteratedBlob := range blobsData {
			iteratedBlobSize := len(iteratedBlob) + ADDRESS_SIZE + BLOB_DATA_LENGTH_SIZE
			if (mergedBlobSize + iteratedBlobSize) <= MAX_BLOB_SIZE_IN_BYTES {
				// adding toAddress
				mergedBlobData = append(mergedBlobData, toAddresses[i].Bytes()...)
				// adding length of the blob data, the length takes always 3 bytes
				mergedBlobData = append(mergedBlobData, blobDataLengthToBytes(iteratedBlobSize)...)
				// add the blob data itself
				mergedBlobData = append(mergedBlobData, iteratedBlob...)

				mergedBlobSize += iteratedBlobSize
				removedBlobs = append(removedBlobs, iteratedBlob)
			}
		}

		blobsData = removeUsedBlobs(blobsData, removedBlobs)
		result = append(result, mergedBlobData)
	}

	// Sort blobsData by length in descending order
	sort.Slice(result, func(i, j int) bool {
		return len(result[i]) > len(result[j])
	})

	return result, nil
}

func blobDataLengthToBytes(length int) []byte {
	return []byte{
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}
}

func removeUsedBlobs(allBlobs, blobsToRemove [][]byte) [][]byte {
	var result [][]byte

OuterLoop:
	for _, s := range allBlobs {
		for _, r := range blobsToRemove {
			// TODO use bytes.Equal or something else?
			if bytes.Equal(s, r) {
				continue OuterLoop
			}
		}
		result = append(result, s)
	}

	return result
}

func mustParseAbi(data string) abi.ABI {
	inoutAbi, err := abi.JSON(strings.NewReader(data))
	if err != nil {
		panic(err.Error())
	}

	return inoutAbi
}

func mustParseMethodAbi(data string, method string) abi.Method {
	inoutAbi := mustParseAbi(data)
	return inoutAbi.Methods[method]
}

func formatPeekerError(format string, args ...any) ([]byte, error) {
	err := fmt.Errorf(format, args...)
	return []byte(err.Error()), err
}

type suaveRuntime struct {
	suaveContext *SuaveContext
}

var _ SuaveRuntime = &suaveRuntime{}

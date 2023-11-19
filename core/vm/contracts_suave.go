package vm

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/stretchr/testify/assert"
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

/* Blob merging precompiles */
func MergeBlobData(toAddresses []common.Address, blobsData [][]byte) ([][]byte, error) {
	fmt.Printf("MergeBlobData - number of separate blobs: %v\n", len(blobsData))
	fmt.Println("MergeBlobData - start")
	// TODO remove this method and put it all just into mergeBlobData
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

	fmt.Println("MergeBlobData - checks passed")

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

	fmt.Println("MergeBlobData - end")
	fmt.Printf("MergeBlobData - number of merged blobs: %v\n", len(result))

	return result, nil
}

func (b *suaveRuntime) mergeBlobData(toAddresses []common.Address, blobsData [][]byte) ([][]byte, error) {
	return MergeBlobData(toAddresses, blobsData)
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

/* WIP tests for mergeBlobData */
// TODO refactor tests to workflow_test.go with proper usage of solidity contract
const (
	MAX_BLOB_SIZE_IN_BYTES = 1024 * 128 // 131072
)

const (
	TEST_ADDRESS_ONE   = "0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5"
	TEST_ADDRESS_TWO   = "0x758b8178A9A4B7206D1f648c4a77C515CbaC7000"
	TEST_ADDRESS_THREE = "0x814FaE9f487206471B6B0D713cD51a2D35980000"
	TEST_ADDRESS_FOUR  = "0x763c396673F9c391DCe3361A9A71C8E161388000"
	TEST_ADDRESS_FIVE  = "0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b7"
)

var ALL_TEST_ADDRESSES []string

func init() {
	ALL_TEST_ADDRESSES = []string{
		TEST_ADDRESS_ONE,
		TEST_ADDRESS_TWO,
		TEST_ADDRESS_THREE,
		TEST_ADDRESS_FOUR,
		TEST_ADDRESS_FIVE,
	}
}

func pickRandomNumber(maxNumber int) int {
	mrand.Seed(time.Now().UnixNano())
	return mrand.Intn(maxNumber)
}

func pickRandomBlobDataSize() int {
	return pickRandomNumber(MAX_BLOB_SIZE_IN_BYTES + 1)
}

func generateRandomByteArray(length int) ([]byte, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomBytes := make([]byte, length)

	for i := range randomBytes {
		n, err := crand.Int(crand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return nil, err
		}
		randomBytes[i] = charset[n.Int64()]
	}

	return randomBytes, nil
}

func TestMergeBlobDataThrowOnInvalidInput(t *testing.T) {
	randomByteSlice, _ := generateRandomByteArray(MAX_BLOB_SIZE_IN_BYTES + 1)
	_, err := MergeBlobData([][]byte{[]byte(TEST_ADDRESS_ONE)}, [][]byte{randomByteSlice})
	assert.NotNil(t, err, "Did not throw on blob data that are bigger than the max.")
}

func TestMergeBlobDataOkWithRandomValidInput(t *testing.T) {
	blobDatasCount := 20
	blobDatas := make([][]byte, blobDatasCount)
	toAddresses := make([][]byte, blobDatasCount)
	for i := 0; i < blobDatasCount; i++ {
		randomByteSlice, _ := generateRandomByteArray(pickRandomBlobDataSize())
		blobDatas[i] = randomByteSlice
		toAddresses[i] = []byte(ALL_TEST_ADDRESSES[pickRandomNumber(len(ALL_TEST_ADDRESSES))])
	}
	_, err := MergeBlobData(toAddresses, blobDatas)
	assert.Nil(t, err, "Incorrectly throwed error on blob data that are valid.")
}

func TestMergeBlobDataWithMultipleBlobsResult(t *testing.T) {
	// max blob size: 131072
	// [100000, 30000, 120000, 1000, 35000] -> [
	//		130090 (130000 + 90 (offsets)),
	// 		121090 (121000 + 90 (offsets)),
	// 		35045 (35000 + 45 (offsets))
	// ]
	// flow:
	//  1) take highest number (120000), check if we can find any blob we can merge to
	//  2) we can merge 120000 + 1000 => 121000 blob
	//  3) remove 120000 + 1000 blobs
	//  4) take next remaining highest number (100000), check if we can find any blob we can merge to
	//  5) we can merge 100000 + 30000 => 130000 blob
	//  6) remove 100000 + 30000 blobs
	//  7) only 35000 blob remains, add a new blob
	//  8) done
	a, _ := generateRandomByteArray(100000)
	b, _ := generateRandomByteArray(30000)
	c, _ := generateRandomByteArray(120000)
	d, _ := generateRandomByteArray(1000)
	e, _ := generateRandomByteArray(35000)
	allBlobs := [][]byte{a, b, c, d, e}
	allToAddresses := [][]byte{
		[]byte(TEST_ADDRESS_ONE),
		[]byte(TEST_ADDRESS_TWO),
		[]byte(TEST_ADDRESS_THREE),
		[]byte(TEST_ADDRESS_FOUR),
		[]byte(TEST_ADDRESS_FIVE),
	}
	result, err := MergeBlobData(allToAddresses, allBlobs)
	assert.Nil(t, err, "Threw error on valid specific data.")
	assert.Equal(t, 3, len(result), "Result does not have 3 blobs.")
	assert.Equal(t, 130090, len(result[0]), "Largest blob should have 130090 length.")
	assert.Equal(t, 121090, len(result[1]), "Second largest blob should have 121090 length.")
	assert.Equal(t, 35045, len(result[2]), "Third largest blob should have 35045 length.")
}

func TestMergeBlobDataWithOffsetsOverlappingIntoSecondBlob(t *testing.T) {
	// max blob size: 131072
	// [100000, 30000, 1000] -> [
	//	130090 (130000 + 90 (offsets))
	//  1045 (1000 + 45 (offsets))
	// ]
	a, _ := generateRandomByteArray(100000)
	b, _ := generateRandomByteArray(30000)
	c, _ := generateRandomByteArray(1000)
	allBlobs := [][]byte{a, b, c}
	allToAddresses := [][]byte{
		[]byte(TEST_ADDRESS_ONE),
		[]byte(TEST_ADDRESS_TWO),
		[]byte(TEST_ADDRESS_THREE),
	}
	result, err := MergeBlobData(allToAddresses, allBlobs)
	assert.Nil(t, err, "Threw error on valid specific data.")
	assert.Equal(t, 2, len(result), "Result does not have 2 blob.")
	assert.Equal(t, 130090, len(result[0]), "Largest blob should have 130090 length.")
	assert.Equal(t, 1045, len(result[1]), "Second largest blob should have 1045 length.")
}

func TestMergeBlobDataSingleBlobResult(t *testing.T) {
	// max blob size: 131072
	// [100000, 4000, 5000, 2000] -> [
	//		110180 (110000 + 180 (offsets))
	// ]
	a, _ := generateRandomByteArray(100000)
	b, _ := generateRandomByteArray(4000)
	c, _ := generateRandomByteArray(5000)
	d, _ := generateRandomByteArray(2000)
	allBlobs := [][]byte{a, b, c, d}
	allToAddresses := [][]byte{
		[]byte(TEST_ADDRESS_ONE),
		[]byte(TEST_ADDRESS_TWO),
		[]byte(TEST_ADDRESS_THREE),
		[]byte(TEST_ADDRESS_FOUR),
	}
	result, err := MergeBlobData(allToAddresses, allBlobs)
	assert.Nil(t, err, "Threw error on valid specific data.")
	assert.Equal(t, 1, len(result), "Result does not have 1 blob.")
	assert.Equal(t, 111180, len(result[0]), "Largest blob should have 111180 length.")
}

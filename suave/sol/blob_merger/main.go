package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	_ "embed"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/suave/e2e"
	"github.com/ethereum/go-ethereum/suave/sdk"
	"github.com/flashbots/suapp-examples/framework"
)

// TODO move this file to workflow_test.go

var (
	// This is the address we used when starting the MEVM
	exNodeEthAddr = common.HexToAddress("b5feafbdd752ad52afb7e1bd2e40432a485bbb7f")
	exNodeNetAddr = "http://localhost:8545"
	// This account is funded in your local SUAVE network
	// address: 0xBE69d72ca5f88aCba033a063dF5DBe43a4148De0
	fundedAccount = newPrivKeyFromHex(
		"91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12",
	)
	blobMergerArtifact = e2e.BlobMergerContract
)

func main() {
	// setup
	fr := framework.New()
	rpcClient, _ := rpc.Dial(exNodeNetAddr)
	mevmClt := sdk.NewClient(rpcClient, fundedAccount.priv, exNodeEthAddr)
	testAddr1 := framework.GeneratePrivKey()
	testAddr2 := framework.GeneratePrivKey()
	fundBalance := big.NewInt(100000000000000000)
	fr.FundAccount(testAddr1.Address(), fundBalance)
	fr.FundAccount(testAddr2.Address(), fundBalance)

	// deploy contract
	var blobMargerContract *sdk.Contract
	txnResult, err := sdk.DeployContract(blobMergerArtifact.Code, mevmClt)
	if err != nil {
		e := fmt.Errorf("failed to deploy contract: %v", err)
		fmt.Println(e)
	}
	receipt, err := txnResult.Wait()
	if err != nil {
		e := fmt.Errorf("failed to wait for transaction result: %v", err)
		fmt.Println(e)
	}
	if receipt.Status == 0 {
		e := fmt.Errorf("failed to deploy contract: %v", err)
		fmt.Println(e)
	}
	fmt.Printf("- Blob Merger contract deployed: %s\n", receipt.ContractAddress)
	blobMargerContract = sdk.GetContract(receipt.ContractAddress, blobMergerArtifact.Abi, mevmClt)

	// test
	// todo gen blob data
	testBlobData := []byte("test blob data")

	fmt.Println("(rollup) Send blob data with confidential request")

	// uint64 decryptionCondition, address[] memory bidAllowedPeekers, address[] memory bidAllowedStores
	bidId, err := blobMargerContract.SendTransaction("submitBlobData", []interface{}{uint64(420), []common.Address{exNodeEthAddr}, []common.Address{}}, testBlobData)
	if err != nil {
		fmt.Printf("Error when calling SendTransaction: %s", err)
		return
	}

	fmt.Print(bidId)

	fmt.Println("(builder) Get merged blobs")
	blobMargerContract.Address().Hex()

	// TODO Replace with your bid data
	bid1 := [16]byte{}
	bid2 := [16]byte{}
	bids := [][16]byte{bid1, bid2}

	data, err := blobMergerArtifact.Abi.Pack("getMergedBlobData", bids)
	if err != nil {
		fmt.Printf("Error when calling Abi.Pack: %s", err)
		return
	}

	callMsg := ethereum.CallMsg{
		From: testAddr1.Address(),
		To:   (*common.Address)(blobMargerContract.Address().Bytes()),
		Data: data,
	}
	fmt.Printf("%+v\n", callMsg)
	val, err := mevmClt.RPC().CallContract(context.Background(), callMsg, nil)

	if err != nil {
		e := fmt.Errorf("failed to call contract: %v", err)
		fmt.Println(e)
	}
	// results
	fmt.Printf("We have %d of marged blobs", len(val))
	fmt.Println("Without merging we'd have 10 blobs")
}

// UTILS
type privKey struct {
	priv *ecdsa.PrivateKey
}

func newPrivKeyFromHex(hex string) *privKey {
	key, err := crypto.HexToECDSA(hex)
	if err != nil {
		panic(fmt.Sprintf("failed to parse private key: %v", err))
	}
	return &privKey{priv: key}
}

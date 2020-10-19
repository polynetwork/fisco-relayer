/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package manager

import (
	"context"
	rand2 "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	bind2 "github.com/FISCO-BCOS/go-sdk/abi/bind"
	"github.com/FISCO-BCOS/go-sdk/client"
	types2 "github.com/FISCO-BCOS/go-sdk/core/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/pkg/errors"
	"github.com/polynetwork/fisco-relayer/config"
	"github.com/polynetwork/fisco-relayer/db"
	"github.com/polynetwork/fisco-relayer/go_abi/eccd_abi"
	"github.com/polynetwork/fisco-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/fisco-relayer/log"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/consensus/vbft/config"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"math/rand"
	"strconv"
	"strings"

	"math/big"
	"time"

	"github.com/polynetwork/fisco-relayer/tools"

	polytypes "github.com/polynetwork/poly/core/types"
)

var (
	// ErrNoCode is returned by call and transact operations for which the requested
	// recipient contract to operate on does not exist in the state db or does not
	// have any code associated with it (i.e. suicided).
	ErrNoCode = errors.New("no contract code at given address")

	// This error is raised when attempting to perform a pending state action
	// on a backend that doesn't implement PendingContractCaller.
	ErrNoPendingState = errors.New("backend does not support pending state")

	// This error is returned by WaitDeployed if contract creation leaves an
	// empty contract behind.
	ErrNoCodeAfterDeploy = errors.New("no contract code after deployment")
)

const (
	ChanLen = 64
)

type PolyManager struct {
	config        *config.ServiceConfig
	polySdk       *sdk.PolySdk
	currentHeight uint32
	contractAbi   *abi.ABI
	exitChan      chan int
	db            *db.BoltDB
	fisSender     *FiscoSender
}

type BoundContract struct {
	address    ethcommon.Address        // Deployment address of the contract on the Ethereum blockchain
	abi        abi.ABI                  // Reflect based ABI to access the correct Ethereum methods
	caller     bind2.ContractCaller     // Read interface to interact with the blockchain
	transactor bind2.ContractTransactor // Write interface to interact with the blockchain
	filterer   bind2.ContractFilterer   // Event filtering to interact with the blockchain
}

type FiscoSender struct {
	client      *client.Client
	acc         ethcommon.Address
	polySdk     *sdk.PolySdk
	cmap        map[string]chan *EthTxInfo
	config      *config.ServiceConfig
	contractAbi *abi.ABI
	c           *BoundContract
}

func NewPolyManager(servCfg *config.ServiceConfig, startblockHeight uint32, polySdk *sdk.PolySdk, fiscosdk *client.Client, boltDB *db.BoltDB) (*PolyManager, error) {
	contractabi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return nil, err
	}

	fisSender := &FiscoSender{
		client:      fiscosdk,
		acc:         ethcommon.HexToAddress("0x34f00110bad3236f01468799d44fe04d7deb25f0"),
		polySdk:     polySdk,
		cmap:        make(map[string]chan *EthTxInfo),
		config:      servCfg,
		contractAbi: &contractabi,
	}

	return &PolyManager{
		exitChan:      make(chan int),
		config:        servCfg,
		polySdk:       polySdk,
		currentHeight: startblockHeight,
		contractAbi:   &contractabi,
		db:            boltDB,
		fisSender:     fisSender,
	}, nil
}

func (this *PolyManager) findLatestHeight() uint32 {

	address := ethcommon.HexToAddress(this.config.FiscoConfig.ECCDContractAddress)
	instance, err := eccd_abi.NewEthCrossChainData(address, this.fisSender.client)
	if err != nil {
		log.Errorf("findLatestHeight - new eth cross chain failed: %s", err.Error())
		return 0
	}
	height, err := instance.GetCurEpochStartHeight(this.fisSender.client.GetCallOpts())
	if err != nil {
		log.Errorf("findLatestHeight - GetLatestHeight failed: %s", err.Error())
		return 0
	}
	return uint32(height)
}

func (this *PolyManager) init() bool {
	if this.currentHeight > 0 {
		log.Infof("PolyManager init - start height from flag: %d", this.currentHeight)
		return true
	}
	this.currentHeight = this.db.GetPolyHeight()
	latestHeight := this.findLatestHeight()
	if latestHeight > this.currentHeight {
		this.currentHeight = latestHeight
		log.Infof("PolyManager init - latest height from ECCM: %d", this.currentHeight)
		return true
	}
	log.Infof("PolyManager init - latest height from DB: %d", this.currentHeight)

	return true
}

func (this *PolyManager) MonitorChain() {
	ret := this.init()
	if ret == false {
		log.Errorf("MonitorChain - init failed\n")
	}
	monitorTicker := time.NewTicker(config.ONT_MONITOR_INTERVAL)
	var blockHandleResult bool
	for {
		select {
		case <-monitorTicker.C:
			latestheight, err := this.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("MonitorChain - get poly chain block height error: %s", err)
				continue
			}
			latestheight--
			if latestheight-this.currentHeight < config.ONT_USEFUL_BLOCK_NUM {
				continue
			}
			log.Infof("MonitorChain - poly chain current height: %d", latestheight)
			blockHandleResult = true
			for this.currentHeight <= latestheight-config.ONT_USEFUL_BLOCK_NUM {
				blockHandleResult = this.handleDepositEvents(this.currentHeight)
				if blockHandleResult == false {
					break
				}
				this.currentHeight++
			}
			if err = this.db.UpdatePolyHeight(this.currentHeight - 1); err != nil {
				log.Errorf("MonitorChain - failed to save height of poly: %v", err)
			}
		case <-this.exitChan:
			return
		}
	}
}

func (this *PolyManager) HandleDepositEvents(height uint32) {
	this.handleDepositEvents(height)
}

func (this *PolyManager) HandleCommitHeader(height uint32) {
	hdr, err := this.polySdk.GetHeaderByHeight(height)
	if err != nil {
		log.Errorf("HandleCommitHeader - GetNodeHeader on height :%d failed", height)
	}
	this.fisSender.commitHeader(hdr)
}

func (this *PolyManager) handleDepositEvents(height uint32) bool {
	lastEpoch := this.findLatestHeight()
	hdr, err := this.polySdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}
	isCurr := lastEpoch < height+1
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, info); err != nil {
		log.Errorf("failed to unmarshal ConsensusPayload for height %d: %v", height+1, err)
		return false
	}
	isEpoch := hdr.NextBookkeeper != common.ADDRESS_EMPTY && info.NewChainConfig != nil
	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = this.polySdk.GetHeaderByHeight(lastEpoch + 1)
		proof, _ := this.polySdk.GetMerkleProof(height+1, lastEpoch+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = this.polySdk.GetHeaderByHeight(height + 2)
		proof, _ := this.polySdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	cnt := 0
	events, err := this.polySdk.GetSmartContractEventByBlock(height)
	for err != nil {
		log.Errorf("handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
	}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == this.config.PolyConfig.EntranceContractAddress {
				states := notify.States.([]interface{})
				method, _ := states[0].(string)
				if method != "makeProof" {
					continue
				}
				if uint64(states[2].(float64)) != this.config.FiscoConfig.SideChainId {
					continue
				}
				proof, err := this.polySdk.GetCrossStatesProof(hdr.Height-1, states[5].(string))
				if err != nil {
					log.Errorf("handleDepositEvents - failed to get proof for key %s: %v", states[5].(string), err)
					continue
				}
				auditpath, _ := hex.DecodeString(proof.AuditPath)
				value, _, _, _ := tools.ParseAuditpath(auditpath)
				param := &common2.ToMerkleValue{}
				if err := param.Deserialization(common.NewZeroCopySource(value)); err != nil {
					log.Errorf("handleDepositEvents - failed to deserialize MakeTxParam (value: %x, err: %v)", value, err)
					continue
				}
				var isTarget bool
				if len(this.config.TargetContracts) > 0 {
					toContractStr := ethcommon.BytesToAddress(param.MakeTxParam.ToContractAddress).String()
					for k, v := range this.config.TargetContracts {
						if k == toContractStr {
							if len(v["inbound"]) == 0 {
								isTarget = true
								break
							}
							for _, id := range v["inbound"] {
								if id == param.FromChainID {
									isTarget = true
									break
								}
							}
							if isTarget {
								break
							}
						}
					}
					if !isTarget {
						continue
					}
				}
				cnt++

				// temporarily ignore the error for tx
				this.fisSender.commitDepositEventsWithHeader(hdr, param, hp, anchor, event.TxHash, auditpath)
			}
		}
	}
	if cnt == 0 && isEpoch && isCurr {
		// 发送Fisco交易
		return this.fisSender.commitHeader(hdr)
	}

	return true
}

func (this *PolyManager) Stop() {
	this.exitChan <- 1
	close(this.exitChan)
	log.Infof("poly chain manager exit.")
}

func (this *FiscoSender) sendTxToEth(info *EthTxInfo) error {

	//nonce := this.nonceManager.GetAddressNonce(this.acc.Address)
	//tx := types.NewTransaction(nonce, info.contractAddr, big.NewInt(0), info.gasLimit, info.gasPrice, info.txData)
	//signedtx, err := this.keyStore.SignTransaction(tx, this.acc, this.pwd)
	//if err != nil {
	//	this.nonceManager.ReturnNonce(this.acc.Address, nonce)
	//	return fmt.Errorf("commitDepositEventsWithHeader - sign raw tx error and return nonce %d: %v", nonce, err)
	//}
	tx, err := this.transact(this.client.GetTransactOpts(), info.contractAddr, big.NewInt(0), info.gasLimit, info.gasPrice, info.txData)

	//this.client.SendTransaction(this.client.GetTransactOpts(),)
	//err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {

		return fmt.Errorf("commitDepositEventsWithHeader - send transaction error and return : %v\n", err)
	}
	hash := tx.Hash()

	isSuccess := this.waitTransactionConfirm(info.polyTxHash, hash)
	if isSuccess {
		log.Infof("successful to relay tx to ethereum: (eth_hash: %s,  poly_hash: %s)",
			hash.String(), info.polyTxHash)
	} else {
		log.Errorf("failed to relay tx to ethereum: (eth_hash: %s, poly_hash: %s)",
			hash.String(), info.polyTxHash)
	}
	return nil
}

// // ensureContext is a helper method to ensure a context is not nil, even if the
// // user specified it as such.
func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.TODO()
	}
	return ctx
}

func (c *BoundContract) generateSignedTx(opts *bind2.TransactOpts, contract *ethcommon.Address, input []byte) (*types2.Transaction, error) {
	var err error

	// Ensure a valid value field and resolve the account nonce
	value := opts.Value
	if value == nil {
		value = new(big.Int)
	}
	// generate random Nonce between 0 - 2^250 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(250), nil).Sub(max, big.NewInt(1))
	//Generate cryptographically strong pseudo-random between 0 - max
	nonce, err := rand2.Int(rand2.Reader, max)
	if err != nil {
		//error handling
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Figure out the gas allowance and gas price values
	gasPrice := opts.GasPrice
	if gasPrice == nil {
		// default value
		gasPrice = big.NewInt(30000000)
	}

	gasLimit := opts.GasLimit
	if gasLimit == nil {
		// Gas estimation cannot succeed without code for method invocations
		if contract != nil {
			if code, err := c.transactor.PendingCodeAt(ensureContext(opts.Context), c.address); err != nil {
				return nil, err
			} else if len(code) == 0 {
				return nil, ErrNoCode
			}
		}
		// If the contract surely has code (or code is not needed), we set a default value to the transaction
		gasLimit = big.NewInt(30000000)
	}

	var blockLimit *big.Int
	blockLimit, err = c.transactor.GetBlockLimit(ensureContext(opts.Context))
	if err != nil {
		return nil, err
	}

	var chainID *big.Int
	chainID, err = c.transactor.GetChainID(ensureContext(opts.Context))
	if err != nil {
		return nil, err
	}

	var groupID *big.Int
	groupID = c.transactor.GetGroupID()
	if groupID == nil {
		return nil, fmt.Errorf("failed to get the group ID")
	}

	// Create the transaction, sign it and schedule it for execution
	var rawTx *types2.Transaction
	str := ""
	extraData := []byte(str)
	if contract == nil {
		rawTx = types2.NewContractCreation(nonce, value, gasLimit, gasPrice, blockLimit, input, chainID, groupID, extraData, c.transactor.SMCrypto())
	} else {
		rawTx = types2.NewTransaction(nonce, c.address, value, gasLimit, gasPrice, blockLimit, input, chainID, groupID, extraData, c.transactor.SMCrypto())
	}
	if opts.Signer == nil {
		return nil, errors.New("no signer to authorize the transaction with")
	}
	signedTx, err := opts.Signer(types2.HomesteadSigner{}, opts.From, rawTx)
	if err != nil {
		return nil, err
	}
	return signedTx, nil
}
func (this *FiscoSender) transact1(opts *bind2.TransactOpts, contract *ethcommon.Address, input []byte) (*types2.Transaction, error) {
	var err error
	//c := this.c
	//opts.From = ethcommon.HexToAddress("0x34f00110bad3236f01468799d44fe04d7deb25f0")
	contractabi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return nil, err
	}

	c := &BoundContract{
		address:    ethcommon.HexToAddress("0xfB6836019B7643bf88E8131d5a176C6e490EDF33"),
		abi:        contractabi,
		caller:     this.client,
		transactor: this.client,
		filterer:   this.client,
	}

	signedTx, err := c.generateSignedTx(opts, contract, input)
	if err != nil {
		return nil, err
	}

	if err = c.transactor.SendTransaction(ensureContext(opts.Context), signedTx); err != nil {
		return nil, err
	}
	return signedTx, nil
}

func (this *FiscoSender) transact(opts *bind2.TransactOpts, contract ethcommon.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, input []byte) (*types2.Transaction, error) {
	var err error
	//c := this.c
	//opts.From = ethcommon.HexToAddress("0x34f00110bad3236f01468799d44fe04d7deb25f0")
	contractabi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return nil, err
	}

	c := &BoundContract{
		address:    contract,
		abi:        contractabi,
		caller:     this.client,
		transactor: this.client,
		filterer:   this.client,
	}
	// Ensure a valid value field and resolve the account nonce
	//value := opts.Value
	value := big.NewInt(0)
	if value == nil {
		value = new(big.Int)
	}
	// generate random Nonce between 0 - 2^250 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(250), nil).Sub(max, big.NewInt(1))
	//Generate cryptographically strong pseudo-random between 0 - max
	nonce, err := rand2.Int(rand2.Reader, max)
	if err != nil {
		//error handling
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Figure out the gas allowance and gas price values
	//gasPrice := opts.GasPrice
	if gasPrice == nil {
		// default value
		gasPrice = big.NewInt(30000000)
	}

	//gasLimit := opts.GasLimit
	//gasLimit:=big.NewInt(gasLimit)
	//if gasLimit == nil {
	//	// Gas estimation cannot succeed without code for method invocations
	//	//if contract != nil {
	//	if code, err := c.transactor.PendingCodeAt(ensureContext(opts.Context), c.address); err != nil {
	//		return nil, err
	//	} else if len(code) == 0 {
	//		return nil, ErrNoCode
	//	}
	//	//}
	//	// If the contract surely has code (or code is not needed), we set a default value to the transaction
	//	gasLimit = big.NewInt(30000000)
	//}

	var blockLimit *big.Int
	blockLimit, err = c.transactor.GetBlockLimit(ensureContext(opts.Context))
	if err != nil {
		return nil, err
	}

	var chainID *big.Int
	chainID, err = c.transactor.GetChainID(ensureContext(opts.Context))
	log.Infof("chainID: %d", chainID)
	chainID = new(big.Int).SetUint64(uint64(1))
	if err != nil {
		return nil, err
	}

	var groupID *big.Int
	groupID = new(big.Int).SetUint64(uint64(1))
	if groupID == nil {
		return nil, fmt.Errorf("failed to get the group ID")
	}

	// Create the transaction, sign it and schedule it for execution
	var rawTx *types2.Transaction
	str := ""
	extraData := []byte(str)
	//if contract == nil {
	//	rawTx = types2.NewContractCreation(nonce, value, gasLimit, gasPrice, blockLimit, input, chainID, groupID, extraData, c.transactor.SMCrypto())
	//} else {
	log.Infof("contract %s", contract.Hex())
	log.Infof("opts.From : %s ,nonce %d ,  groupID %s,chainID %s , gasLimit %s , gasPrice %s , blockLimit  %s  ", opts.From.Hex(), nonce, groupID, chainID, new(big.Int).SetUint64(gasLimit), gasPrice, blockLimit)
	rawTx = types2.NewTransaction(nonce, contract, amount, new(big.Int).SetUint64(gasLimit), gasPrice, blockLimit, input, chainID, groupID, extraData, c.transactor.SMCrypto())
	//}
	if opts.Signer == nil {
		return nil, errors.New("no signer to authorize the transaction with")
	}
	//ethcommon.HexToAddress("0x34f00110bad3236f01468799d44fe04d7deb25f0")
	signedTx, err := opts.Signer(types2.HomesteadSigner{}, opts.From, rawTx)
	log.Infof("rawTx: %s , signedTx:%s", rawTx.Hash().Hex(), signedTx.Hash().Hex())
	if err != nil {
		return nil, err
	}
	if err := c.transactor.SendTransaction(ensureContext(opts.Context), signedTx); err != nil {
		log.Fatal(err)
		return nil, err
	}
	return signedTx, nil
}

func (this *FiscoSender) commitDepositEventsWithHeader(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, polyTxHash string, rawAuditPath []byte) bool {
	var (
		sigs       []byte
		headerData []byte
	)
	if anchorHeader != nil && headerProof != "" {
		for _, sig := range anchorHeader.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	} else {
		for _, sig := range header.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	}
	eccdAddr := ethcommon.HexToAddress(this.config.FiscoConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, this.client)
	eccmAddr := ethcommon.HexToAddress(this.config.FiscoConfig.ECCMContractAddress)
	eccm, err := eccm_abi.NewEthCrossChainManager(eccmAddr, this.client)

	if err != nil {
		panic(fmt.Errorf("failed to new eccm: %v", err))
	}
	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])
	res, _ := eccd.CheckIfFromChainTxExist(this.client.GetCallOpts(), param.FromChainID, fromTx)
	if res {
		log.Debugf("already relayed to eth: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
		return true
	}
	//log.Infof("poly proof with header, height: %d, key: %s, proof: %s", header.Height-1, string(key), proof.AuditPath)

	rawProof, _ := hex.DecodeString(headerProof)
	var rawAnchor []byte
	if anchorHeader != nil {
		rawAnchor = anchorHeader.GetMessage()
	}
	headerData = header.GetMessage()

	trans, err := eccm.VerifyHeaderAndExecuteTx(this.client.GetTransactOpts(), rawAuditPath, headerData, rawProof, rawAnchor, sigs)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - err:" + err.Error())
		return false
	}
	log.Infof("contractAbi trans txData is : %s", trans.Hash().Hex())

	return true
}

func (this *FiscoSender) commitHeader(header *polytypes.Header) bool {
	headerdata := header.GetMessage()
	var (
		bookkeepers []keypair.PublicKey
		sigs        []byte
	)
	//gasPrice, err := this.ethClient.SuggestGasPrice(context.Background())
	//if err != nil {
	//	log.Errorf("commitHeader - get suggest sas price failed error: %s", err.Error())
	//	return false
	//}
	for _, sig := range header.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		newsig, _ := signature.ConvertToEthCompatible(temp)
		sigs = append(sigs, newsig...)
	}

	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(header.ConsensusPayload, blkInfo); err != nil {
		log.Errorf("commitHeader - unmarshal blockInfo error: %s", err)
		return false
	}

	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, tools.GetNoCompresskey(key)...)
	}

	eccmAddr := ethcommon.HexToAddress(this.config.FiscoConfig.ECCMContractAddress)
	eccm, err := eccm_abi.NewEthCrossChainManager(eccmAddr, this.client)

	tx, err := eccm.ChangeBookKeeper(this.client.GetTransactOpts(), headerdata, publickeys, sigs)
	if err != nil {
		log.Fatal(err)
		return false
	}
	log.Infof("ChangeBookKeeper:%s", tx.Hash().Hex())

	//hash := header.Hash()
	//txhash := tx.Hash()
	//
	//isSuccess := this.waitTransactionConfirm(fmt.Sprintf("header: %d", header.Height), txhash)
	//if isSuccess {
	//	log.Infof("successful to relay poly header to ethereum: (header_hash: %s, height: %d, eth_txhash: %s)",
	//		hash.ToHexString(), header.Height, txhash.String())
	//} else {
	//	log.Errorf("failed to relay poly header to ethereum: (header_hash: %s, height: %d, eth_txhash: %s)",
	//		hash.ToHexString(), header.Height, txhash.String())
	//}
	return true
}

func (this *FiscoSender) getRouter() string {
	return strconv.FormatInt(rand.Int63n(this.config.RoutineNum), 10)
}

func (this *FiscoSender) waitTransactionConfirm(polyTxHash string, hash ethcommon.Hash) bool {
	for {
		time.Sleep(time.Second * 1)
		_, err := this.client.GetTransactionByHash(context.Background(), polyTxHash)
		if err != nil {
			continue
		}
		log.Debugf("( eth_transaction %s, poly_tx %s ) is pending: %v", hash.String(), polyTxHash)

		receipt, err := this.client.TransactionReceipt(context.Background(), hash)
		if err != nil {
			continue
		}

		log.Debugf("( eth_transaction %s, Status %s ) is pending: %v", hash.String(), receipt.Status)

		return true
	}
}

type EthTxInfo struct {
	txData       []byte
	gasLimit     uint64
	gasPrice     *big.Int
	contractAddr ethcommon.Address
	polyTxHash   string
}

type FiscoTxInfo struct {
	txData       []byte
	gasLimit     uint64
	gasPrice     *big.Int
	contractAddr *ethcommon.Address
	polyTxHash   string
}

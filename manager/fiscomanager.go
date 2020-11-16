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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/FISCO-BCOS/go-sdk/core/types"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/polynetwork/fisco-relayer/config"
	"github.com/polynetwork/fisco-relayer/db"
	"github.com/polynetwork/fisco-relayer/go_abi/eccm_abi"
	"github.com/polynetwork/fisco-relayer/go_abi/fiscox_abi"
	"github.com/polynetwork/fisco-relayer/go_abi/lock_proxy_abi"
	"github.com/polynetwork/fisco-relayer/log"
	"github.com/polynetwork/poly-io-test/chains/ont"
	"github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/status-im/keycard-go/hexutils"
	"github.com/tjfoc/gmsm/pkcs12"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/FISCO-BCOS/go-sdk/client"
	comm "github.com/ethereum/go-ethereum/common"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	scom "github.com/polynetwork/poly/native/service/header_sync/common"
	"github.com/tjfoc/gmsm/sm2"
	//"io/ioutil"
	"strconv"
	"time"
	"unsafe"
	//
)

type FiscoManager struct {
	config        *config.ServiceConfig
	client        *client.Client
	currentHeight uint64
	forceHeight   uint64
	polySdk       *sdk.PolySdk
	polySigner    *sdk.Account
	db            *db.BoltDB
	caSet         *scom.CertTrustChain
}

func NewFiscoManager(servconfig *config.ServiceConfig, startheight uint64, startforceheight uint64, ontsdk *sdk.PolySdk, client *client.Client, boltDB *db.BoltDB) (*FiscoManager, error) {
	var wallet *sdk.Wallet
	var err error
	if !common.FileExisted(servconfig.PolyConfig.WalletFile) {
		wallet, err = ontsdk.CreateWallet(servconfig.PolyConfig.WalletFile)
		if err != nil {
			return nil, err
		}
	} else {
		wallet, err = ontsdk.OpenWallet(servconfig.PolyConfig.WalletFile)
		if err != nil {
			log.Errorf("FiscoManager - wallet open error: %s", err.Error())
			return nil, err
		}
	}
	signer, err := wallet.GetDefaultAccount([]byte(servconfig.PolyConfig.WalletPwd))
	if err != nil || signer == nil {
		signer, err = wallet.NewDefaultSettingAccount([]byte(servconfig.PolyConfig.WalletPwd))
		if err != nil {
			log.Errorf("FiscoManager - wallet password error")
			return nil, err
		}

		err = wallet.Save()
		if err != nil {
			return nil, err
		}
	}
	log.Infof("FiscoManager - poly address: %s", signer.Address.ToBase58())

	caSet := &scom.CertTrustChain{
		Certs: make([]*sm2.Certificate, 2),
	}
	keysCa, err := ioutil.ReadFile(servconfig.FiscoConfig.AgencyPath)
	blkAgency, _ := pem.Decode(keysCa)
	caSet.Certs[0], err = sm2.ParseCertificate(blkAgency.Bytes)
	if err != nil {
		return nil, err
	}
	keysCert, err := ioutil.ReadFile(servconfig.FiscoConfig.NodePath)
	blk, _ := pem.Decode(keysCert)
	caSet.Certs[1], _ = sm2.ParseCertificate(blk.Bytes)

	mgr := &FiscoManager{
		config:        servconfig,
		currentHeight: startheight,
		forceHeight:   startforceheight,
		client:        client,
		polySdk:       ontsdk,
		polySigner:    signer,
		db:            boltDB,
		caSet:         caSet,
	}
	return mgr, nil

}
func bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))

}
func (this *FiscoManager) init() error {
	lastest := this.findFiscoLastestHeight()
	heightInDB := this.db.GetFiscoHeight()
	if this.forceHeight > 0 {
		this.currentHeight = this.forceHeight
	} else if lastest <= heightInDB {
		this.currentHeight = heightInDB
	} else {
		this.currentHeight = lastest
	}
	log.Infof("FiscoManager init - start height: %d", this.currentHeight)

	return nil
}

func (this *FiscoManager) findFiscoLastestHeight() uint64 {
	height := uint64(0)
	for k := range this.config.TargetContracts {
		res, _ := this.polySdk.Native.Ccm.GetFiscoHeightInProcessing(this.config.FiscoConfig.SideChainId, comm.HexToAddress(k).Bytes())
		if uint64(res) < height {
			height = uint64(res)
		}
	}
	return height
}

func (this *FiscoManager) MonitorChain() {
	fetchBlockTicker := time.NewTicker(config.ETH_MONITOR_INTERVAL)
	for {
		select {
		case <-fetchBlockTicker.C:
			log.Info("in !!!!")
			currHeight, err := this.BlockNumber()
			log.Info("out !!!!")
			if err != nil {
				log.Fatalf("FiscoManager MonitorChain - failed to get current fisco height: %v", err)
				continue
			}
			height := uint64(currHeight)
			log.Debugf("FiscoManager MonitorChain - fiscobcos chain current height: %d", height)
			if height <= this.currentHeight {
				continue
			}
			for this.currentHeight < height {
				if this.FetchLockDepositEvents(this.currentHeight + 1) {
					this.currentHeight++
					if err := this.db.UpdateFiscoHeight(this.currentHeight); err != nil {
						log.Errorf("FiscoManager MonitorChain - save new height %d to DB failed: %v", this.currentHeight, err)
					}
				}
			}
		}
	}
}

/**
 * ClientVersion
 */
func (this *FiscoManager) ClientVersion() {

	cv, err := this.client.GetClientVersion(context.Background())
	if err != nil {
		log.Fatalf("client version not found: %v", err)
	}

	log.Infof("client version:\n%s", cv)

}

func (this *FiscoManager) GetBlance(acc string) {

	fiscoxAddress := comm.HexToAddress(this.config.FiscoConfig.PETHContractAddress)
	account := comm.HexToAddress(acc)

	fiscox, err := fiscox_abi.NewFISCOX(fiscoxAddress, this.client)
	if err != nil {

		log.Fatal(err)
	}
	total, err := fiscox.TotalSupply(this.client.GetCallOpts())

	log.Infof("TotalSupply:%d", total)

	lockAddr := comm.HexToAddress(this.config.FiscoConfig.LOCKContractAddress)

	balance0, err := fiscox.BalanceOf(this.client.GetCallOpts(), lockAddr)

	log.Infof("%s balance is %d:", this.config.FiscoConfig.LOCKContractAddress, balance0)

	balance1, err := fiscox.BalanceOf(this.client.GetCallOpts(), account)

	log.Infof("%s balance is %d:", acc, balance1)

	decimal, err := fiscox.Decimals(this.client.GetCallOpts())
	if err != nil {

		log.Fatal(err)
	}
	log.Infof("decimal  is : %d", decimal)

	allow, err := fiscox.Allowance(this.client.GetCallOpts(), account, lockAddr)
	log.Infof("allow  is : %d", allow)

}

func (this *FiscoManager) GetProxyHash() {
	address := comm.HexToAddress(this.config.FiscoConfig.LOCKContractAddress)
	instance1, err := lock_proxy_abi.NewLockProxy(address, this.client)
	if err != nil {
		log.Fatal(err)
	}
	lock_proxy := &lock_proxy_abi.LockProxySession{Contract: instance1, CallOpts: *this.client.GetCallOpts(), TransactOpts: *this.client.GetTransactOpts()}

	hex1, err := lock_proxy.ProxyHashMap(2)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("ProxyHashMap tx: %v", hexutils.BytesToHex(hex1))

	fromAssetHash := comm.HexToAddress(this.config.FiscoConfig.PETHContractAddress)
	hex2, err := lock_proxy.AssetHashMap(fromAssetHash, 2)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("AssetHashMap tx: %v", hexutils.BytesToHex(hex2))
}

func (this *FiscoManager) BindHash() {

	address := comm.HexToAddress(this.config.FiscoConfig.LOCKContractAddress)
	instance1, err := lock_proxy_abi.NewLockProxy(address, this.client)
	if err != nil {
		log.Fatal(err)
	}
	lock_proxy := &lock_proxy_abi.LockProxySession{Contract: instance1, CallOpts: *this.client.GetCallOpts(), TransactOpts: *this.client.GetTransactOpts()}

	fromAddress := comm.HexToAddress("0x2EEA349947f93c3B9b74FBcf141e102ADD510eCE")
	trans, recp, err := lock_proxy.BindProxyHash(2, fromAddress.Bytes())
	if err != nil {
		log.Fatalf("BindProxyHash error: %v", err)
	}
	log.Infof("BindProxyHash tx: %v,recp :%v", trans.Hash().Hex(), recp.BlockNumber)
	fromAssetHash := comm.HexToAddress(this.config.FiscoConfig.PETHContractAddress)

	toAssetHash := comm.HexToAddress("0x0000000000000000000000000000000000000000")
	trans1, recp1, err := lock_proxy.BindAssetHash(fromAssetHash, 2, toAssetHash.Bytes())
	if err != nil {
		log.Fatalf("BindProxyHash error: %v", err)
	}
	log.Infof("BindAssetHash tx: %v,recp:%v", trans1.Hash().Hex(), recp1.BlockNumber)
	_ = instance1
}

func (this *FiscoManager) waitTransactionConfirm(polyTxHash string, hash comm.Hash) bool {
	for {
		time.Sleep(time.Second * 1)
		_, err := this.client.GetTransactionByHash(context.Background(), polyTxHash)
		if err != nil {
			continue
		}
		log.Debugf("( fisco_transaction %s, poly_tx %s ) is pending: %v", hash.String(), polyTxHash)

		receipt, err := this.client.TransactionReceipt(context.Background(), hash)
		if err != nil {
			continue
		}
		log.Debugf("( fisco_transaction %s, Status %s ) is pending: %v", hash.String(), receipt.Status)
		return true
	}
}

func (this *FiscoManager) StartTransact(toAccAddr string, amount int64) {
	lockAddr := comm.HexToAddress(this.config.FiscoConfig.LOCKContractAddress)
	instance1, err := lock_proxy_abi.NewLockProxy(lockAddr, this.client)
	if err != nil {
		log.Fatal(err)
	}
	lock_proxy := &lock_proxy_abi.LockProxySession{Contract: instance1, CallOpts: *this.client.GetCallOpts(), TransactOpts: *this.client.GetTransactOpts()}

	fiscoxAddress := comm.HexToAddress(this.config.FiscoConfig.PETHContractAddress)

	if err != nil {
		log.Fatal(err)
	}

	toAcc := comm.HexToAddress(toAccAddr)
	tx1, recp2, err := lock_proxy.Lock(fiscoxAddress, 2, toAcc.Bytes(), big.NewInt(amount))

	if err != nil {
		log.Fatalf("Lock proxy: %v", err)
		return
	}
	log.Infof("Lock tx1 %s,recp2:%v", tx1.Hash().Hex(), recp2.BlockNumber)

}

/**
 * BlockNumber
 */
func (this *FiscoManager) BlockNumber() (int64, error) {
	bn, err := this.client.GetBlockNumber(context.Background())
	if err != nil {
		return 0, fmt.Errorf("block number not found: %v", err)
	}
	str, err := strconv.Unquote(bytes2str(bn))
	if err != nil {
		return 0, fmt.Errorf("ParseInt: %v", err)
	}
	height, err := strconv.ParseInt(str, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("ParseInt: %v", err)
	}
	return height, nil
}

func (this *FiscoManager) SyncFiscoGenesisHeader(poly *sdk.PolySdk, ecmAddr string) {
	eccm := comm.HexToAddress(ecmAddr)

	eccmContract, err := eccm_abi.NewEthCrossChainManager(eccm, this.client)
	if err != nil {
		fmt.Println(err)
	}

	gB, err := poly.GetBlockByHeight(60000)
	if err != nil {
		fmt.Println(err)
	}

	if err != nil {
		panic(err)
	}
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(gB.Header.ConsensusPayload, info); err != nil {
		panic(fmt.Errorf("commitGenesisHeader - unmarshal blockInfo error: %s", err))
	}

	var bookkeepers []keypair.PublicKey
	for _, peer := range info.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)

	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, ont.GetOntNoCompressKey(key)...)
	}
	rawHdr := gB.Header.ToArray()

	trans, recp, err := eccmContract.InitGenesisBlock(this.client.GetTransactOpts(), rawHdr, publickeys)

	log.Infof("InitGenesisBlock: %s,recp:%v", trans.Hash().Hex(), recp.BlockNumber)
}

type BlockRes struct {
	Transactions []string `json:"transactions"`
}

func (this *FiscoManager) FetchLockDepositEvents(height uint64) bool {
	eccmAddress := comm.HexToAddress(this.config.FiscoConfig.ECCMContractAddress)
	eccmContract, err := eccm_abi.NewEthCrossChainManager(eccmAddress, this.client)
	if err != nil {
		return false
	}
	blk, err := this.client.GetBlockByNumber(context.Background(), strconv.FormatUint(height, 10), false)
	if err != nil {
		log.Errorf("fetchLockDepositEvents - GetBlockByNumber error :%s", err.Error())
		return false
	}
	res := &BlockRes{}
	err = json.Unmarshal(blk, res)
	if err != nil {
		log.Errorf("fetchLockDepositEvents - Unmarshal error :%s", err.Error())
		return false
	}
	for _, tx := range res.Transactions {
		recp, err := this.client.TransactionReceipt(context.Background(), comm.HexToHash(tx))
		if err != nil {
			log.Errorf("fetchLockDepositEvents - TransactionReceipt error: %s", err.Error())
			continue
		}
		if recp.Status != 0 {
			continue
		}
		for _, v := range recp.Logs {
			if v.Address != strings.ToLower(this.config.FiscoConfig.ECCMContractAddress) {
				continue
			}
			topics := make([]comm.Hash, len(v.Topics))
			for i, t := range v.Topics {
				topics[i] = comm.HexToHash(t.(string))
			}
			rawData, _ := hex.DecodeString(strings.TrimPrefix(v.Data, "0x"))
			evt, err := eccmContract.ParseCrossChainEvent(types.Log{
				Address: comm.HexToAddress(v.Address),
				Topics:  topics,
				Data:    rawData,
			})
			if err != nil || evt == nil {
				continue
			}

			var isTarget bool
			if len(this.config.TargetContracts) > 0 {
				toContractStr := evt.ProxyOrAssetContract.String()
				for k, v := range this.config.TargetContracts {
					ok := k == toContractStr
					if ok {
						if len(v["outbound"]) == 0 {
							isTarget = true
							break
						}
						for _, id := range v["outbound"] {
							if id == evt.ToChainId {
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
			hash, err := this.SendCrossChainInfoWithRaw(evt.Rawdata)
			if err != nil {
				log.Errorf("failed to send for fisco tx %s: (error: %v, raw_data: %x)", tx, err, rawData)
				continue
			}
			log.Infof("fetchLockDepositEvents - successful to send cross chain info: (tx_hash: %s, fisco_hash: %s)",
				hash.ToHexString(), tx)
		}
	}

	return true
}

func (this *FiscoManager) SendCrossChainInfoWithRaw(rawInfo []byte) (common.Uint256, error) {
	keys, err := ioutil.ReadFile(this.config.FiscoConfig.KeyPath)
	if err != nil {
		return common.UINT256_EMPTY, fmt.Errorf("failed to read fisco key: %v", err)
	}
	blk, _ := pem.Decode(keys)

	var sig []byte
	if !this.config.FiscoConfig.IsGM {
		hasher := sm2.SHA256.New()
		hasher.Write(rawInfo)
		raw := hasher.Sum(nil)
		key, err := pkcs12.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
		priv := key.(*ecdsa.PrivateKey)
		sig, err = priv.Sign(rand.Reader, raw, nil)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	} else {
		key, err := sm2.ParsePKCS8UnecryptedPrivateKey(blk.Bytes)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("failed to ParsePKCS8UnecryptedPrivateKey: %v", err)
		}
		sig, err = key.Sign(rand.Reader, rawInfo, nil)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}

	txHash, err := this.polySdk.Native.Ccm.RelayCrossChainInfo(this.config.FiscoConfig.SideChainId, sig, rawInfo, this.polySigner.Address[:], this.caSet, this.polySigner)
	if err != nil { //TODO: if pre-execute failed, maybe should deal with that error.
		log.Fatalf("RelayCrossChainInfo err: %v", err)
		return common.UINT256_EMPTY, err
	}
	return txHash, nil
}

func (this *FiscoManager) SendCrossChainInfo(param common2.MakeTxParam) (common.Uint256, error) {
	sink := common.NewZeroCopySink(nil)
	param.Serialization(sink)
	rawInfo := sink.Bytes()

	return this.SendCrossChainInfoWithRaw(rawInfo)
}

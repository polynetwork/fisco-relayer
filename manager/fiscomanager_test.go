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
	"fmt"
	conf2 "github.com/FISCO-BCOS/go-sdk/conf"
	"github.com/polynetwork/fisco-relayer/config"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"testing"
)

func setUpPoly(poly *poly_go_sdk.PolySdk, RpcAddr string) error {
	poly.NewRpcClient().SetAddress(RpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}

func TestFiscoManager_SendCrossChainInfo(t *testing.T) {
	conf := &config.ServiceConfig{}
	conf.PolyConfig = &config.PolyConfig{}
	conf.ETHConfig = &config.ETHConfig{}
	conf.Config = &conf2.Config{}

	conf.PolyConfig.RestURL = "http://106.75.226.11:40336"
	conf.PolyConfig.WalletFile = "/Users/zou/go/src/github.com/ontio/poly-io-test/.wallets/wallet.dat"
	conf.PolyConfig.WalletPwd = "4cUYqGj2yib718E7ZmGQc"

	conf.Config.Cert = "gmnode.crt"
	conf.Config.Key = "gmnode.key"
	conf.ETHConfig.SideChainId = 6

	poly := poly_go_sdk.NewPolySdk()
	err := setUpPoly(poly, conf.PolyConfig.RestURL)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewFiscoManager(conf, 0, 0, poly, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	param := &common.MakeTxParam{}
	param.Method = "test"

	txhash, err := mgr.SendCrossChainInfo(*param)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(txhash.ToHexString())
}
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
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/FISCO-BCOS/go-sdk/client"
	"github.com/FISCO-BCOS/go-sdk/conf"
	"github.com/polynetwork/fisco-relayer/cmd"
	"github.com/polynetwork/fisco-relayer/config"
	"github.com/polynetwork/fisco-relayer/db"
	"github.com/polynetwork/fisco-relayer/log"
	"github.com/polynetwork/fisco-relayer/manager"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/urfave/cli"

	"os"
	"os/signal"
	"runtime"
	"syscall"
)

var ConfigPath string

var LogDir string
var StartHeight uint64
var PolyStartHeight uint64
var StartForceHeight uint64

func setupApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "FISCO BCOS relayer Service"
	app.Action = startServer
	app.Version = config.Version
	app.Copyright = "Copyright in 2020 The Ontology Authors"
	app.Flags = []cli.Flag{
		cmd.LogLevelFlag,
		cmd.ConfigPathFlag,
		cmd.ConfigPathFisco,
		cmd.EthStartFlag,
		cmd.EthStartForceFlag,
		cmd.PolyStartFlag,
		cmd.LogDir,
	}
	app.Commands = []cli.Command{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}
	return app
}

func startServer(ctx *cli.Context) {
	// get all cmd flag
	logLevel := ctx.GlobalInt(cmd.GetFlagName(cmd.LogLevelFlag))

	ld := ctx.GlobalString(cmd.GetFlagName(cmd.LogDir))
	log.InitLog(logLevel, ld, log.Stdout)

	ConfigPath = ctx.GlobalString(cmd.GetFlagName(cmd.ConfigPathFlag))

	ethstart := ctx.GlobalUint64(cmd.GetFlagName(cmd.EthStartFlag))
	if ethstart > 0 {
		StartHeight = ethstart
	}

	StartForceHeight = 0
	ethstartforce := ctx.GlobalUint64(cmd.GetFlagName(cmd.EthStartForceFlag))
	if ethstartforce > 0 {
		StartForceHeight = ethstartforce
	}
	polyStart := ctx.GlobalUint64(cmd.GetFlagName(cmd.PolyStartFlag))
	if polyStart > 0 {
		PolyStartHeight = polyStart
	}

	// read config
	servConfig := config.NewServiceConfig(ConfigPath)
	if servConfig == nil {
		log.Errorf("startServer - create config failed!")
		return
	}

	// create poly sdk
	polySdk := sdk.NewPolySdk()
	err := setUpPoly(polySdk, servConfig.PolyConfig.RestURL)
	if err != nil {
		log.Errorf("startServer - failed to setup poly sdk: %v", err)
		return
	}

	// create fisco sdk
	ConfigPath = ctx.GlobalString(cmd.GetFlagName(cmd.ConfigPathFisco))

	config := &conf.ParseConfig(ConfigPath)[0]

	servConfig.Config = config

	fiscosdk, err := client.Dial(servConfig.Config)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("dsd")

	// test helloworld
	//testFiscoHello(fiscosdk)

	var boltDB *db.BoltDB
	if servConfig.BoltDbPath == "" {
		boltDB, err = db.NewBoltDB("boltdb")
	} else {
		boltDB, err = db.NewBoltDB(servConfig.BoltDbPath)
	}
	if err != nil {
		log.Fatalf("db.NewWaitingDB error:%s", err)
		return
	}

	initFiscoServer(servConfig, polySdk, fiscosdk, boltDB)

	initPolyServer(servConfig, polySdk, fiscosdk, boltDB)

	waitToExit()

}

func setUpPoly(poly *sdk.PolySdk, RpcAddr string) error {
	poly.NewRpcClient().SetAddress(RpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			log.Infof("waitToExit - FISCO relayer received exit signal:%v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}

func initFiscoServer(servConfig *config.ServiceConfig, polysdk *sdk.PolySdk, fiscosdk *client.Client, boltDB *db.BoltDB) {
	mgr, err := manager.NewFiscoManager(servConfig, StartHeight, StartForceHeight, polysdk, fiscosdk, boltDB)
	if err != nil {
		log.Error("initFiscoServer - fisco service start err: %s", err.Error())
		return
	}

	//go mgr.BindHash()

	//go mgr.StartTransact()

	//go mgr.FetchLockDepositEvents(427)

	go mgr.MonitorChain()

	//go mgr.SyncFiscoGenesisHeader(polysdk,servConfig.ETHConfig.ECCMContractAddress)

	//param := common2.MakeTxParam{}
	//param.TxHash = common.UINT256_EMPTY.ToArray()
	//param.Method = "te11st"
	//param.ToChainID = 2
	//param.CrossChainID = IntToBytes(5)
	//sink := common.NewZeroCopySink(nil)
	//param.Serialization(sink)
	//
	//tx, err := mgr.SendCrossChainInfo(param)
	//
	//fmt.Println("transaction hash: ", tx.ToHexString())
	//go mgr.MonitorDeposit()
	//go mgr.CheckDeposit()
}

func initPolyServer(servConfig *config.ServiceConfig, polysdk *sdk.PolySdk, fiscosdk *client.Client, boltDB *db.BoltDB) {
	mgr, err := manager.NewPolyManager(servConfig, uint32(PolyStartHeight), polysdk, fiscosdk, boltDB)
	if err != nil {
		log.Error("initPolyServer - PolyServer service start failed: %v", err)
		return
	}

	go mgr.MonitorChain()

	//go mgr.HandleCommitHeader(110565)
	//go mgr.HandleDepositEvents(105958)

}
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func main() {
	log.Infof("main - FISCO BCOS relayer starting...")
	if err := setupApp().Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

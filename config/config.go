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
package config

import (
	"encoding/json"
	"fmt"
	"github.com/FISCO-BCOS/go-sdk/conf"
	_ "github.com/FISCO-BCOS/go-sdk/conf"
	"github.com/polynetwork/fisco-relayer/log"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const (
	ETH_MONITOR_INTERVAL = time.Second
	ONT_MONITOR_INTERVAL = time.Second

	ETH_USEFUL_BLOCK_NUM      = 3
	ETH_PROOF_USERFUL_BLOCK   = 12
	ONT_USEFUL_BLOCK_NUM      = 1
	DEFAULT_CONFIG_FILE_NAME  = "./config_default.json"
	DEFAULT_CONFIG_FISCO_NAME = "./config.toml"
	Version                   = "1.0"

	DEFAULT_LOG_LEVEL = log.InfoLog
)

//type ETH struct {
//	Chain             string // eth or etc
//	ChainId           uint64
//	RpcAddress        string
//	ConfirmedBlockNum uint
//	//Tokens            []*Token
//}

type ServiceConfig struct {
	PolyConfig      *PolyConfig
	FiscoConfig     *FiscoConfig
	Config          *conf.Config
	BoltDbPath      string
	RoutineNum      int64
	TargetContracts map[string]map[string][]uint64
}

type PolyConfig struct {
	RestURL                 string
	EntranceContractAddress string
	WalletFile              string
	WalletPwd               string
}

// Config contains configuration items for sdk
type FiscoConfig struct {
	SideChainId         uint64
	ECCMContractAddress string
	ECCDContractAddress string
	LOCKContractAddress string
	PETHContractAddress string
	NodePath            string
	KeyPath             string
	AgencyPath          string
	IsGM bool
}

type ONTConfig struct {
	RestURL string
}

func ReadFile(fileName string) ([]byte, error) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: open file %s error %s", fileName, err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Errorf("ReadFile: File %s close error %s", fileName, err)
		}
	}()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: ioutil.ReadAll %s error %s", fileName, err)
	}
	return data, nil
}

func NewServiceConfig(configFilePath string) *ServiceConfig {

	fileContent, err := ReadFile(configFilePath)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}
	servConfig := &ServiceConfig{}

	//fiscoConfig:=ParseConfig(configFiscoPath)[0]
	//
	//fmt.Println("chainId",fiscoConfig.ChainID)

	err = json.Unmarshal(fileContent, servConfig)
	if err != nil {
		log.Errorf("NewServiceConfig: failed, err: %s", err)
		return nil
	}

	return servConfig
}

// ParseConfig parses the configuration from toml config file
func ParseConfig(cfgFile string) []conf.Config {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()
	viper.SetConfigType("toml")
	config := new(conf.Config)
	var configs []conf.Config
	viper.SetDefault("SMCrypto", false)
	viper.SetDefault("Network.Type", "rpc")
	viper.SetDefault("Network.CAFile", "ca.crt")
	viper.SetDefault("Network.Key", "sdk.key")
	viper.SetDefault("Network.Cert", "sdk.crt")
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if viper.IsSet("Chain") {
			if viper.IsSet("Chain.ChainID") {
				config.ChainID = int64(viper.GetInt("Chain.ChainID"))
			} else {
				fmt.Println("Chain.ChainID has not been set")
				os.Exit(1)
			}
			if viper.IsSet("Chain.SMCrypto") {
				config.IsSMCrypto = viper.GetBool("Chain.SMCrypto")
			} else {
				fmt.Println("SMCrypto has not been set")
				os.Exit(1)
			}
		} else {
			fmt.Println("Chain has not been set")
			os.Exit(1)
		}
		if viper.IsSet("Account") {
			accountKeyFile := viper.GetString("Account.KeyFile")
			keyHex, curve, _, err := LoadECPrivateKeyFromPEM(accountKeyFile)
			if err != nil {
				fmt.Println("parse private key failed, err:", err)
				os.Exit(1)
			}
			if config.IsSMCrypto && curve != sm2p256v1 {
				fmt.Printf("smcrypto must use sm2p256v1 private key, but found %s", curve)
				os.Exit(1)
			}
			if !config.IsSMCrypto && curve != secp256k1 {
				fmt.Printf("must use secp256k1 private key, but found %s", curve)
				os.Exit(1)
			}
			// fmt.Printf("key=%s,curve=%s", keyHex, curve)
			config.PrivateKey = keyHex
		} else {
			fmt.Println("Network has not been set")
			os.Exit(1)
		}
		if viper.IsSet("Network") {
			connectionType := viper.GetString("Network.Type")
			if strings.EqualFold(connectionType, "rpc") {
				config.IsHTTP = true
			} else if strings.EqualFold(connectionType, "channel") {
				config.IsHTTP = false
			} else {
				fmt.Printf("Network.Type %s is not supported, use channel", connectionType)
			}
			config.CAFile = viper.GetString("Network.CAFile")
			config.Key = viper.GetString("Network.Key")
			config.Cert = viper.GetString("Network.Cert")
			var connections []struct {
				GroupID int
				NodeURL string
			}
			if viper.IsSet("Network.Connection") {
				err := viper.UnmarshalKey("Network.Connection", &connections)
				if err != nil {
					fmt.Printf("Parse Network.Connection failed. err:%v", err)
					os.Exit(1)
				}
				for i := range connections {
					configs = append(configs, *config)
					configs[i].GroupID = connections[i].GroupID
					configs[i].NodeURL = connections[i].NodeURL
				}
			} else {
				fmt.Printf("Network.Connection has not been set.")
				os.Exit(1)
			}
		} else {
			fmt.Println("Network has not been set")
			os.Exit(1)
		}
	} else {
		fmt.Printf("err message is : %v", err)
	}

	// fmt.Printf("configuration is %+v\n", configs)
	return configs
}

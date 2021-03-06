// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package eccmp_abi

import (
	"math/big"
	"strings"

	"github.com/FISCO-BCOS/go-sdk/abi"
	"github.com/FISCO-BCOS/go-sdk/abi/bind"
	"github.com/FISCO-BCOS/go-sdk/core/types"
	"github.com/FISCO-BCOS/go-sdk/event"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = abi.U256
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ContextABI is the input ABI used to generate the binding from.
const ContextABI = "[{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// Context is an auto generated Go binding around a Solidity contract.
type Context struct {
	ContextCaller     // Read-only binding to the contract
	ContextTransactor // Write-only binding to the contract
	ContextFilterer   // Log filterer for contract events
}

// ContextCaller is an auto generated read-only Go binding around a Solidity contract.
type ContextCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContextTransactor is an auto generated write-only Go binding around a Solidity contract.
type ContextTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContextFilterer is an auto generated log filtering Go binding around a Solidity contract events.
type ContextFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContextSession is an auto generated Go binding around a Solidity contract,
// with pre-set call and transact options.
type ContextSession struct {
	Contract     *Context          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ContextCallerSession is an auto generated read-only Go binding around a Solidity contract,
// with pre-set call options.
type ContextCallerSession struct {
	Contract *ContextCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// ContextTransactorSession is an auto generated write-only Go binding around a Solidity contract,
// with pre-set transact options.
type ContextTransactorSession struct {
	Contract     *ContextTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// ContextRaw is an auto generated low-level Go binding around a Solidity contract.
type ContextRaw struct {
	Contract *Context // Generic contract binding to access the raw methods on
}

// ContextCallerRaw is an auto generated low-level read-only Go binding around a Solidity contract.
type ContextCallerRaw struct {
	Contract *ContextCaller // Generic read-only contract binding to access the raw methods on
}

// ContextTransactorRaw is an auto generated low-level write-only Go binding around a Solidity contract.
type ContextTransactorRaw struct {
	Contract *ContextTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContext creates a new instance of Context, bound to a specific deployed contract.
func NewContext(address common.Address, backend bind.ContractBackend) (*Context, error) {
	contract, err := bindContext(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Context{ContextCaller: ContextCaller{contract: contract}, ContextTransactor: ContextTransactor{contract: contract}, ContextFilterer: ContextFilterer{contract: contract}}, nil
}

// NewContextCaller creates a new read-only instance of Context, bound to a specific deployed contract.
func NewContextCaller(address common.Address, caller bind.ContractCaller) (*ContextCaller, error) {
	contract, err := bindContext(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContextCaller{contract: contract}, nil
}

// NewContextTransactor creates a new write-only instance of Context, bound to a specific deployed contract.
func NewContextTransactor(address common.Address, transactor bind.ContractTransactor) (*ContextTransactor, error) {
	contract, err := bindContext(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContextTransactor{contract: contract}, nil
}

// NewContextFilterer creates a new log filterer instance of Context, bound to a specific deployed contract.
func NewContextFilterer(address common.Address, filterer bind.ContractFilterer) (*ContextFilterer, error) {
	contract, err := bindContext(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContextFilterer{contract: contract}, nil
}

// bindContext binds a generic wrapper to an already deployed contract.
func bindContext(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ContextABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Context *ContextRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Context.Contract.ContextCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Context *ContextRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Context.Contract.ContextTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Context *ContextRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _Context.Contract.ContextTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Context *ContextCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Context.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Context *ContextTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Context.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Context *ContextTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _Context.Contract.contract.Transact(opts, method, params...)
}

// EthCrossChainManagerProxyABI is the input ABI used to generate the binding from.
const EthCrossChainManagerProxyABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"pauseEthCrossChainManager\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getEthCrossChainManager\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"unpause\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"isOwner\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_newEthCrossChainManagerAddr\",\"type\":\"address\"}],\"name\":\"upgradeEthCrossChainManager\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"pause\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"unpauseEthCrossChainManager\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"_ethCrossChainManagerAddr\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Paused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Unpaused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"}]"

// EthCrossChainManagerProxyFuncSigs maps the 4-byte function signature to its string representation.
var EthCrossChainManagerProxyFuncSigs = map[string]string{
	"483bf041": "getEthCrossChainManager()",
	"ede8e529": "isOwner()",
	"5089e2c8": "owner()",
	"f4fbb0c8": "pause()",
	"215a9825": "pauseEthCrossChainManager()",
	"d4bc9601": "paused()",
	"d86e29e2": "renounceOwnership()",
	"16cad12a": "transferOwnership(address)",
	"63c37526": "unpause()",
	"fa6ec386": "unpauseEthCrossChainManager()",
	"f0ee0e19": "upgradeEthCrossChainManager(address)",
}

// EthCrossChainManagerProxyBin is the compiled bytecode used for deploying new contracts.
var EthCrossChainManagerProxyBin = "0x608060405234801561001057600080fd5b5060405160208061107b8339810180604052602081101561003057600080fd5b505160006100456401000000006100c4810204565b60008054600160a060020a031916600160a060020a0383169081178255604051929350917f5c7c30d4a0f08950cb23be4132957b357fa5dfdb0fcf218f81b86a1c036e47d0908290a3506000805460a060020a60ff021916905560018054600160a060020a031916600160a060020a03929092169190911790556100c8565b3390565b610fa4806100d76000396000f3fe6080604052600436106100a05760003560e060020a90048063d4bc960111610068578063d4bc96011461015e578063d86e29e214610173578063ede8e52914610188578063f0ee0e191461019d578063f4fbb0c8146101d0578063fa6ec386146101e5576100a0565b806316cad12a146100a5578063215a9825146100da578063483bf041146101035780635089e2c81461013457806363c3752614610149575b600080fd5b3480156100b157600080fd5b506100d8600480360360208110156100c857600080fd5b5035600160a060020a03166101fa565b005b3480156100e657600080fd5b506100ef610253565b604080519115158252519081900360200190f35b34801561010f57600080fd5b50610118610409565b60408051600160a060020a039092168252519081900360200190f35b34801561014057600080fd5b5061011861047e565b34801561015557600080fd5b506100ef61048d565b34801561016a57600080fd5b506100ef610500565b34801561017f57600080fd5b506100d8610510565b34801561019457600080fd5b506100ef6105b4565b3480156101a957600080fd5b506100ef600480360360208110156101c057600080fd5b5035600160a060020a03166105d8565b3480156101dc57600080fd5b506100ef610970565b3480156101f157600080fd5b506100ef6109dc565b6102026105b4565b1515610247576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b61025081610ba6565b50565b600061025d6105b4565b15156102a2576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b60005460a060020a900460ff1615610305576040805160e160020a636381e58902815260206004820152601060248201527f5061757361626c653a2070617573656400000000000000000000000000000000604482015290519081900360640190fd5b600154600160a060020a0316610319610970565b151561035a5760405160e160020a636381e589028152600401808060200182810382526030815260200180610e816030913960400191505060405180910390fd5b80600160a060020a031663f4fbb0c86040518163ffffffff1660e060020a028152600401602060405180830381600087803b15801561039857600080fd5b505af11580156103ac573d6000803e3d6000fd5b505050506040513d60208110156103c257600080fd5b505115156104055760405160e160020a636381e58902815260040180806020018281038252602b815260200180610f1c602b913960400191505060405180910390fd5b5090565b6000805460a060020a900460ff161561046d576040805160e160020a636381e58902815260206004820152601060248201527f5061757361626c653a2070617573656400000000000000000000000000000000604482015290519081900360640190fd5b50600154600160a060020a03165b90565b600054600160a060020a031690565b60006104976105b4565b15156104dc576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b6104e4610500565b15156104f25750600161047b565b6104fa610c59565b50600190565b60005460a060020a900460ff1690565b6105186105b4565b151561055d576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b60008054604051600160a060020a03909116907f5c7c30d4a0f08950cb23be4132957b357fa5dfdb0fcf218f81b86a1c036e47d0908390a36000805473ffffffffffffffffffffffffffffffffffffffff19169055565b60008054600160a060020a03166105c9610d21565b600160a060020a031614905090565b60006105e26105b4565b1515610627576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b60005460a060020a900460ff16151561068b576040805160e160020a636381e58902815260206004820152601460248201527f5061757361626c653a206e6f7420706175736564000000000000000000000000604482015290519081900360640190fd5b600154604080517fd4bc96010000000000000000000000000000000000000000000000000000000081529051600160a060020a0390921691829163d4bc9601916004808301926020929190829003018186803b1580156106ea57600080fd5b505afa1580156106fe573d6000803e3d6000fd5b505050506040513d602081101561071457600080fd5b505115156107c75780600160a060020a031663f4fbb0c86040518163ffffffff1660e060020a028152600401602060405180830381600087803b15801561075a57600080fd5b505af115801561076e573d6000803e3d6000fd5b505050506040513d602081101561078457600080fd5b505115156107c75760405160e160020a636381e58902815260040180806020018281038252602f815260200180610dd6602f913960400191505060405180910390fd5b80600160a060020a031663f4e614d2846040518263ffffffff1660e060020a0281526004018082600160a060020a0316600160a060020a03168152602001915050602060405180830381600087803b15801561082257600080fd5b505af1158015610836573d6000803e3d6000fd5b505050506040513d602081101561084c57600080fd5b5051151561088f5760405160e160020a636381e589028152600401808060200182810382526029815260200180610e2b6029913960400191505060405180910390fd5b600083905080600160a060020a031663ede8e5296040518163ffffffff1660e060020a02815260040160206040518083038186803b1580156108d057600080fd5b505afa1580156108e4573d6000803e3d6000fd5b505050506040513d60208110156108fa57600080fd5b5051151561093d5760405160e160020a636381e58902815260040180806020018281038252604b815260200180610eb1604b913960600191505060405180910390fd5b50506001805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a03939093169290921790915590565b600061097a6105b4565b15156109bf576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b6109c7610500565b156109d45750600161047b565b6104fa610d25565b60006109e66105b4565b1515610a2b576040805160e160020a636381e5890281526020600482018190526024820152600080516020610efc833981519152604482015290519081900360640190fd5b60005460a060020a900460ff161515610a8f576040805160e160020a636381e58902815260206004820152601460248201527f5061757361626c653a206e6f7420706175736564000000000000000000000000604482015290519081900360640190fd5b600154604080517f63c375260000000000000000000000000000000000000000000000000000000081529051600160a060020a039092169182916363c375269160048083019260209291908290030181600087803b158015610af057600080fd5b505af1158015610b04573d6000803e3d6000fd5b505050506040513d6020811015610b1a57600080fd5b50511515610b5d5760405160e160020a636381e58902815260040180806020018281038252602d815260200180610e54602d913960400191505060405180910390fd5b610b6561048d565b15156104055760405160e160020a636381e589028152600401808060200182810382526032815260200180610f476032913960400191505060405180910390fd5b600160a060020a0381161515610bf15760405160e160020a636381e589028152600401808060200182810382526026815260200180610e056026913960400191505060405180910390fd5b60008054604051600160a060020a03808516939216917f5c7c30d4a0f08950cb23be4132957b357fa5dfdb0fcf218f81b86a1c036e47d091a36000805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0392909216919091179055565b60005460a060020a900460ff161515610cbd576040805160e160020a636381e58902815260206004820152601460248201527f5061757361626c653a206e6f7420706175736564000000000000000000000000604482015290519081900360640190fd5b6000805474ff0000000000000000000000000000000000000000191690557f44693cadc19db35d7d96cdf4ec424cb6160570279ff61a4d437c15aed7a3f2e4610d04610d21565b60408051600160a060020a039092168252519081900360200190a1565b3390565b60005460a060020a900460ff1615610d88576040805160e160020a636381e58902815260206004820152601060248201527f5061757361626c653a2070617573656400000000000000000000000000000000604482015290519081900360640190fd5b6000805474ff0000000000000000000000000000000000000000191660a060020a1790557f3572985a03189531d14bf182c5069e6eeb1ebd11ac4b5316dd3395136a20af7b610d04610d2156fe5061757365206f6c642045746843726f7373436861696e4d616e6167657220636f6e7472616374206661696c6564214f776e61626c653a206e6577206f776e657220697320746865207a65726f206164647265737345746843726f7373436861696e4d616e616765722075706772616465546f4e6577206661696c656421756e70617573652045746843726f7373436861696e4d616e6167657220636f6e7472616374206661696c65642170617573652045746843726f7373436861696e4d616e6167657250726f787920636f6e7472616374206661696c65642145746843726f7373436861696e4d616e6167657250726f7879206973206e6f74206f776e6572206f66206e65772045746843726f7373436861696e4d616e6167657220636f6e74726163744f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657270617573652045746843726f7373436861696e4d616e6167657220636f6e7472616374206661696c656421756e70617573652045746843726f7373436861696e4d616e6167657250726f787920636f6e7472616374206661696c656421a165627a7a7230582093ad8fb6116999c6146523a8129d2357c31e82b9cfe4e2a07f88d69ef87d09960029"

// DeployEthCrossChainManagerProxy deploys a new contract, binding an instance of EthCrossChainManagerProxy to it.
func DeployEthCrossChainManagerProxy(auth *bind.TransactOpts, backend bind.ContractBackend, _ethCrossChainManagerAddr common.Address) (common.Address, *types.Transaction, *EthCrossChainManagerProxy, error) {
	parsed, err := abi.JSON(strings.NewReader(EthCrossChainManagerProxyABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(EthCrossChainManagerProxyBin), backend, _ethCrossChainManagerAddr)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &EthCrossChainManagerProxy{EthCrossChainManagerProxyCaller: EthCrossChainManagerProxyCaller{contract: contract}, EthCrossChainManagerProxyTransactor: EthCrossChainManagerProxyTransactor{contract: contract}, EthCrossChainManagerProxyFilterer: EthCrossChainManagerProxyFilterer{contract: contract}}, nil
}

func AsyncDeployEthCrossChainManagerProxy(auth *bind.TransactOpts, handler func(*types.Receipt, error), backend bind.ContractBackend, _ethCrossChainManagerAddr common.Address) (*types.Transaction, error) {
	parsed, err := abi.JSON(strings.NewReader(EthCrossChainManagerProxyABI))
	if err != nil {
		return nil, err
	}

	tx, err := bind.AsyncDeployContract(auth, handler, parsed, common.FromHex(EthCrossChainManagerProxyBin), backend, _ethCrossChainManagerAddr)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// EthCrossChainManagerProxy is an auto generated Go binding around a Solidity contract.
type EthCrossChainManagerProxy struct {
	EthCrossChainManagerProxyCaller     // Read-only binding to the contract
	EthCrossChainManagerProxyTransactor // Write-only binding to the contract
	EthCrossChainManagerProxyFilterer   // Log filterer for contract events
}

// EthCrossChainManagerProxyCaller is an auto generated read-only Go binding around a Solidity contract.
type EthCrossChainManagerProxyCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EthCrossChainManagerProxyTransactor is an auto generated write-only Go binding around a Solidity contract.
type EthCrossChainManagerProxyTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EthCrossChainManagerProxyFilterer is an auto generated log filtering Go binding around a Solidity contract events.
type EthCrossChainManagerProxyFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EthCrossChainManagerProxySession is an auto generated Go binding around a Solidity contract,
// with pre-set call and transact options.
type EthCrossChainManagerProxySession struct {
	Contract     *EthCrossChainManagerProxy // Generic contract binding to set the session for
	CallOpts     bind.CallOpts              // Call options to use throughout this session
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// EthCrossChainManagerProxyCallerSession is an auto generated read-only Go binding around a Solidity contract,
// with pre-set call options.
type EthCrossChainManagerProxyCallerSession struct {
	Contract *EthCrossChainManagerProxyCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                    // Call options to use throughout this session
}

// EthCrossChainManagerProxyTransactorSession is an auto generated write-only Go binding around a Solidity contract,
// with pre-set transact options.
type EthCrossChainManagerProxyTransactorSession struct {
	Contract     *EthCrossChainManagerProxyTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                    // Transaction auth options to use throughout this session
}

// EthCrossChainManagerProxyRaw is an auto generated low-level Go binding around a Solidity contract.
type EthCrossChainManagerProxyRaw struct {
	Contract *EthCrossChainManagerProxy // Generic contract binding to access the raw methods on
}

// EthCrossChainManagerProxyCallerRaw is an auto generated low-level read-only Go binding around a Solidity contract.
type EthCrossChainManagerProxyCallerRaw struct {
	Contract *EthCrossChainManagerProxyCaller // Generic read-only contract binding to access the raw methods on
}

// EthCrossChainManagerProxyTransactorRaw is an auto generated low-level write-only Go binding around a Solidity contract.
type EthCrossChainManagerProxyTransactorRaw struct {
	Contract *EthCrossChainManagerProxyTransactor // Generic write-only contract binding to access the raw methods on
}

// NewEthCrossChainManagerProxy creates a new instance of EthCrossChainManagerProxy, bound to a specific deployed contract.
func NewEthCrossChainManagerProxy(address common.Address, backend bind.ContractBackend) (*EthCrossChainManagerProxy, error) {
	contract, err := bindEthCrossChainManagerProxy(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxy{EthCrossChainManagerProxyCaller: EthCrossChainManagerProxyCaller{contract: contract}, EthCrossChainManagerProxyTransactor: EthCrossChainManagerProxyTransactor{contract: contract}, EthCrossChainManagerProxyFilterer: EthCrossChainManagerProxyFilterer{contract: contract}}, nil
}

// NewEthCrossChainManagerProxyCaller creates a new read-only instance of EthCrossChainManagerProxy, bound to a specific deployed contract.
func NewEthCrossChainManagerProxyCaller(address common.Address, caller bind.ContractCaller) (*EthCrossChainManagerProxyCaller, error) {
	contract, err := bindEthCrossChainManagerProxy(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxyCaller{contract: contract}, nil
}

// NewEthCrossChainManagerProxyTransactor creates a new write-only instance of EthCrossChainManagerProxy, bound to a specific deployed contract.
func NewEthCrossChainManagerProxyTransactor(address common.Address, transactor bind.ContractTransactor) (*EthCrossChainManagerProxyTransactor, error) {
	contract, err := bindEthCrossChainManagerProxy(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxyTransactor{contract: contract}, nil
}

// NewEthCrossChainManagerProxyFilterer creates a new log filterer instance of EthCrossChainManagerProxy, bound to a specific deployed contract.
func NewEthCrossChainManagerProxyFilterer(address common.Address, filterer bind.ContractFilterer) (*EthCrossChainManagerProxyFilterer, error) {
	contract, err := bindEthCrossChainManagerProxy(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxyFilterer{contract: contract}, nil
}

// bindEthCrossChainManagerProxy binds a generic wrapper to an already deployed contract.
func bindEthCrossChainManagerProxy(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(EthCrossChainManagerProxyABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _EthCrossChainManagerProxy.Contract.EthCrossChainManagerProxyCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.EthCrossChainManagerProxyTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.EthCrossChainManagerProxyTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _EthCrossChainManagerProxy.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.contract.Transact(opts, method, params...)
}

// GetEthCrossChainManager is a free data retrieval call binding the contract method 0x483bf041.
//
// Solidity: function getEthCrossChainManager() constant returns(address)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCaller) GetEthCrossChainManager(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _EthCrossChainManagerProxy.contract.Call(opts, out, "getEthCrossChainManager")
	return *ret0, err
}

// GetEthCrossChainManager is a free data retrieval call binding the contract method 0x483bf041.
//
// Solidity: function getEthCrossChainManager() constant returns(address)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) GetEthCrossChainManager() (common.Address, error) {
	return _EthCrossChainManagerProxy.Contract.GetEthCrossChainManager(&_EthCrossChainManagerProxy.CallOpts)
}

// GetEthCrossChainManager is a free data retrieval call binding the contract method 0x483bf041.
//
// Solidity: function getEthCrossChainManager() constant returns(address)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCallerSession) GetEthCrossChainManager() (common.Address, error) {
	return _EthCrossChainManagerProxy.Contract.GetEthCrossChainManager(&_EthCrossChainManagerProxy.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCaller) IsOwner(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _EthCrossChainManagerProxy.contract.Call(opts, out, "isOwner")
	return *ret0, err
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) IsOwner() (bool, error) {
	return _EthCrossChainManagerProxy.Contract.IsOwner(&_EthCrossChainManagerProxy.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCallerSession) IsOwner() (bool, error) {
	return _EthCrossChainManagerProxy.Contract.IsOwner(&_EthCrossChainManagerProxy.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x5089e2c8.
//
// Solidity: function owner() constant returns(address)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _EthCrossChainManagerProxy.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x5089e2c8.
//
// Solidity: function owner() constant returns(address)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) Owner() (common.Address, error) {
	return _EthCrossChainManagerProxy.Contract.Owner(&_EthCrossChainManagerProxy.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x5089e2c8.
//
// Solidity: function owner() constant returns(address)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCallerSession) Owner() (common.Address, error) {
	return _EthCrossChainManagerProxy.Contract.Owner(&_EthCrossChainManagerProxy.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _EthCrossChainManagerProxy.contract.Call(opts, out, "paused")
	return *ret0, err
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) Paused() (bool, error) {
	return _EthCrossChainManagerProxy.Contract.Paused(&_EthCrossChainManagerProxy.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyCallerSession) Paused() (bool, error) {
	return _EthCrossChainManagerProxy.Contract.Paused(&_EthCrossChainManagerProxy.CallOpts)
}

// Pause is a paid mutator transaction binding the contract method 0xf4fbb0c8.
//
// Solidity: function pause() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "pause")
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncPause(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0xf4fbb0c8.
//
// Solidity: function pause() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) Pause() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.Pause(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncPause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncPause(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0xf4fbb0c8.
//
// Solidity: function pause() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) Pause() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.Pause(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncPause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncPause(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// PauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x215a9825.
//
// Solidity: function pauseEthCrossChainManager() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) PauseEthCrossChainManager(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "pauseEthCrossChainManager")
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncPauseEthCrossChainManager(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "pauseEthCrossChainManager")
}

// PauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x215a9825.
//
// Solidity: function pauseEthCrossChainManager() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) PauseEthCrossChainManager() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.PauseEthCrossChainManager(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncPauseEthCrossChainManager(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncPauseEthCrossChainManager(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// PauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x215a9825.
//
// Solidity: function pauseEthCrossChainManager() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) PauseEthCrossChainManager() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.PauseEthCrossChainManager(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncPauseEthCrossChainManager(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncPauseEthCrossChainManager(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0xd86e29e2.
//
// Solidity: function renounceOwnership() returns()
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "renounceOwnership")
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncRenounceOwnership(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0xd86e29e2.
//
// Solidity: function renounceOwnership() returns()
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) RenounceOwnership() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.RenounceOwnership(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncRenounceOwnership(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncRenounceOwnership(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0xd86e29e2.
//
// Solidity: function renounceOwnership() returns()
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) RenounceOwnership() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.RenounceOwnership(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncRenounceOwnership(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncRenounceOwnership(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x16cad12a.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "transferOwnership", newOwner)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncTransferOwnership(handler func(*types.Receipt, error), opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x16cad12a.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) TransferOwnership(newOwner common.Address) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.TransferOwnership(&_EthCrossChainManagerProxy.TransactOpts, newOwner)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncTransferOwnership(handler func(*types.Receipt, error), newOwner common.Address) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncTransferOwnership(handler, &_EthCrossChainManagerProxy.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x16cad12a.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.TransferOwnership(&_EthCrossChainManagerProxy.TransactOpts, newOwner)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncTransferOwnership(handler func(*types.Receipt, error), newOwner common.Address) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncTransferOwnership(handler, &_EthCrossChainManagerProxy.TransactOpts, newOwner)
}

// Unpause is a paid mutator transaction binding the contract method 0x63c37526.
//
// Solidity: function unpause() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "unpause")
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncUnpause(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x63c37526.
//
// Solidity: function unpause() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) Unpause() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.Unpause(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncUnpause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncUnpause(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x63c37526.
//
// Solidity: function unpause() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) Unpause() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.Unpause(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncUnpause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncUnpause(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// UnpauseEthCrossChainManager is a paid mutator transaction binding the contract method 0xfa6ec386.
//
// Solidity: function unpauseEthCrossChainManager() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) UnpauseEthCrossChainManager(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "unpauseEthCrossChainManager")
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncUnpauseEthCrossChainManager(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "unpauseEthCrossChainManager")
}

// UnpauseEthCrossChainManager is a paid mutator transaction binding the contract method 0xfa6ec386.
//
// Solidity: function unpauseEthCrossChainManager() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) UnpauseEthCrossChainManager() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.UnpauseEthCrossChainManager(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncUnpauseEthCrossChainManager(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncUnpauseEthCrossChainManager(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// UnpauseEthCrossChainManager is a paid mutator transaction binding the contract method 0xfa6ec386.
//
// Solidity: function unpauseEthCrossChainManager() returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) UnpauseEthCrossChainManager() (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.UnpauseEthCrossChainManager(&_EthCrossChainManagerProxy.TransactOpts)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncUnpauseEthCrossChainManager(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncUnpauseEthCrossChainManager(handler, &_EthCrossChainManagerProxy.TransactOpts)
}

// UpgradeEthCrossChainManager is a paid mutator transaction binding the contract method 0xf0ee0e19.
//
// Solidity: function upgradeEthCrossChainManager(address _newEthCrossChainManagerAddr) returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) UpgradeEthCrossChainManager(opts *bind.TransactOpts, _newEthCrossChainManagerAddr common.Address) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.contract.Transact(opts, "upgradeEthCrossChainManager", _newEthCrossChainManagerAddr)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactor) AsyncUpgradeEthCrossChainManager(handler func(*types.Receipt, error), opts *bind.TransactOpts, _newEthCrossChainManagerAddr common.Address) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.contract.AsyncTransact(opts, handler, "upgradeEthCrossChainManager", _newEthCrossChainManagerAddr)
}

// UpgradeEthCrossChainManager is a paid mutator transaction binding the contract method 0xf0ee0e19.
//
// Solidity: function upgradeEthCrossChainManager(address _newEthCrossChainManagerAddr) returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) UpgradeEthCrossChainManager(_newEthCrossChainManagerAddr common.Address) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.UpgradeEthCrossChainManager(&_EthCrossChainManagerProxy.TransactOpts, _newEthCrossChainManagerAddr)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxySession) AsyncUpgradeEthCrossChainManager(handler func(*types.Receipt, error), _newEthCrossChainManagerAddr common.Address) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncUpgradeEthCrossChainManager(handler, &_EthCrossChainManagerProxy.TransactOpts, _newEthCrossChainManagerAddr)
}

// UpgradeEthCrossChainManager is a paid mutator transaction binding the contract method 0xf0ee0e19.
//
// Solidity: function upgradeEthCrossChainManager(address _newEthCrossChainManagerAddr) returns(bool)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) UpgradeEthCrossChainManager(_newEthCrossChainManagerAddr common.Address) (*types.Transaction, *types.Receipt, error) {
	return _EthCrossChainManagerProxy.Contract.UpgradeEthCrossChainManager(&_EthCrossChainManagerProxy.TransactOpts, _newEthCrossChainManagerAddr)
}

func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyTransactorSession) AsyncUpgradeEthCrossChainManager(handler func(*types.Receipt, error), _newEthCrossChainManagerAddr common.Address) (*types.Transaction, error) {
	return _EthCrossChainManagerProxy.Contract.AsyncUpgradeEthCrossChainManager(handler, &_EthCrossChainManagerProxy.TransactOpts, _newEthCrossChainManagerAddr)
}

// EthCrossChainManagerProxyOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the EthCrossChainManagerProxy contract.
type EthCrossChainManagerProxyOwnershipTransferredIterator struct {
	Event *EthCrossChainManagerProxyOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EthCrossChainManagerProxyOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EthCrossChainManagerProxyOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EthCrossChainManagerProxyOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EthCrossChainManagerProxyOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EthCrossChainManagerProxyOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EthCrossChainManagerProxyOwnershipTransferred represents a OwnershipTransferred event raised by the EthCrossChainManagerProxy contract.
type EthCrossChainManagerProxyOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x000000000000000000000000000000000000000000000000000000005c7c30d4.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*EthCrossChainManagerProxyOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _EthCrossChainManagerProxy.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxyOwnershipTransferredIterator{contract: _EthCrossChainManagerProxy.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x000000000000000000000000000000000000000000000000000000005c7c30d4.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *EthCrossChainManagerProxyOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _EthCrossChainManagerProxy.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EthCrossChainManagerProxyOwnershipTransferred)
				if err := _EthCrossChainManagerProxy.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x000000000000000000000000000000000000000000000000000000005c7c30d4.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) ParseOwnershipTransferred(log types.Log) (*EthCrossChainManagerProxyOwnershipTransferred, error) {
	event := new(EthCrossChainManagerProxyOwnershipTransferred)
	if err := _EthCrossChainManagerProxy.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	return event, nil
}

// EthCrossChainManagerProxyPausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the EthCrossChainManagerProxy contract.
type EthCrossChainManagerProxyPausedIterator struct {
	Event *EthCrossChainManagerProxyPaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EthCrossChainManagerProxyPausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EthCrossChainManagerProxyPaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EthCrossChainManagerProxyPaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EthCrossChainManagerProxyPausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EthCrossChainManagerProxyPausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EthCrossChainManagerProxyPaused represents a Paused event raised by the EthCrossChainManagerProxy contract.
type EthCrossChainManagerProxyPaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x000000000000000000000000000000000000000000000000000000003572985a.
//
// Solidity: event Paused(address account)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) FilterPaused(opts *bind.FilterOpts) (*EthCrossChainManagerProxyPausedIterator, error) {

	logs, sub, err := _EthCrossChainManagerProxy.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxyPausedIterator{contract: _EthCrossChainManagerProxy.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x000000000000000000000000000000000000000000000000000000003572985a.
//
// Solidity: event Paused(address account)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *EthCrossChainManagerProxyPaused) (event.Subscription, error) {

	logs, sub, err := _EthCrossChainManagerProxy.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EthCrossChainManagerProxyPaused)
				if err := _EthCrossChainManagerProxy.contract.UnpackLog(event, "Paused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x000000000000000000000000000000000000000000000000000000003572985a.
//
// Solidity: event Paused(address account)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) ParsePaused(log types.Log) (*EthCrossChainManagerProxyPaused, error) {
	event := new(EthCrossChainManagerProxyPaused)
	if err := _EthCrossChainManagerProxy.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	return event, nil
}

// EthCrossChainManagerProxyUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the EthCrossChainManagerProxy contract.
type EthCrossChainManagerProxyUnpausedIterator struct {
	Event *EthCrossChainManagerProxyUnpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EthCrossChainManagerProxyUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EthCrossChainManagerProxyUnpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EthCrossChainManagerProxyUnpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EthCrossChainManagerProxyUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EthCrossChainManagerProxyUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EthCrossChainManagerProxyUnpaused represents a Unpaused event raised by the EthCrossChainManagerProxy contract.
type EthCrossChainManagerProxyUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x0000000000000000000000000000000000000000000000000000000044693cad.
//
// Solidity: event Unpaused(address account)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) FilterUnpaused(opts *bind.FilterOpts) (*EthCrossChainManagerProxyUnpausedIterator, error) {

	logs, sub, err := _EthCrossChainManagerProxy.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerProxyUnpausedIterator{contract: _EthCrossChainManagerProxy.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x0000000000000000000000000000000000000000000000000000000044693cad.
//
// Solidity: event Unpaused(address account)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *EthCrossChainManagerProxyUnpaused) (event.Subscription, error) {

	logs, sub, err := _EthCrossChainManagerProxy.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EthCrossChainManagerProxyUnpaused)
				if err := _EthCrossChainManagerProxy.contract.UnpackLog(event, "Unpaused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x0000000000000000000000000000000000000000000000000000000044693cad.
//
// Solidity: event Unpaused(address account)
func (_EthCrossChainManagerProxy *EthCrossChainManagerProxyFilterer) ParseUnpaused(log types.Log) (*EthCrossChainManagerProxyUnpaused, error) {
	event := new(EthCrossChainManagerProxyUnpaused)
	if err := _EthCrossChainManagerProxy.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	return event, nil
}

// IEthCrossChainManagerProxyABI is the input ABI used to generate the binding from.
const IEthCrossChainManagerProxyABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"getEthCrossChainManager\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

// IEthCrossChainManagerProxyFuncSigs maps the 4-byte function signature to its string representation.
var IEthCrossChainManagerProxyFuncSigs = map[string]string{
	"483bf041": "getEthCrossChainManager()",
}

// IEthCrossChainManagerProxy is an auto generated Go binding around a Solidity contract.
type IEthCrossChainManagerProxy struct {
	IEthCrossChainManagerProxyCaller     // Read-only binding to the contract
	IEthCrossChainManagerProxyTransactor // Write-only binding to the contract
	IEthCrossChainManagerProxyFilterer   // Log filterer for contract events
}

// IEthCrossChainManagerProxyCaller is an auto generated read-only Go binding around a Solidity contract.
type IEthCrossChainManagerProxyCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IEthCrossChainManagerProxyTransactor is an auto generated write-only Go binding around a Solidity contract.
type IEthCrossChainManagerProxyTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IEthCrossChainManagerProxyFilterer is an auto generated log filtering Go binding around a Solidity contract events.
type IEthCrossChainManagerProxyFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IEthCrossChainManagerProxySession is an auto generated Go binding around a Solidity contract,
// with pre-set call and transact options.
type IEthCrossChainManagerProxySession struct {
	Contract     *IEthCrossChainManagerProxy // Generic contract binding to set the session for
	CallOpts     bind.CallOpts               // Call options to use throughout this session
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// IEthCrossChainManagerProxyCallerSession is an auto generated read-only Go binding around a Solidity contract,
// with pre-set call options.
type IEthCrossChainManagerProxyCallerSession struct {
	Contract *IEthCrossChainManagerProxyCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                     // Call options to use throughout this session
}

// IEthCrossChainManagerProxyTransactorSession is an auto generated write-only Go binding around a Solidity contract,
// with pre-set transact options.
type IEthCrossChainManagerProxyTransactorSession struct {
	Contract     *IEthCrossChainManagerProxyTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                     // Transaction auth options to use throughout this session
}

// IEthCrossChainManagerProxyRaw is an auto generated low-level Go binding around a Solidity contract.
type IEthCrossChainManagerProxyRaw struct {
	Contract *IEthCrossChainManagerProxy // Generic contract binding to access the raw methods on
}

// IEthCrossChainManagerProxyCallerRaw is an auto generated low-level read-only Go binding around a Solidity contract.
type IEthCrossChainManagerProxyCallerRaw struct {
	Contract *IEthCrossChainManagerProxyCaller // Generic read-only contract binding to access the raw methods on
}

// IEthCrossChainManagerProxyTransactorRaw is an auto generated low-level write-only Go binding around a Solidity contract.
type IEthCrossChainManagerProxyTransactorRaw struct {
	Contract *IEthCrossChainManagerProxyTransactor // Generic write-only contract binding to access the raw methods on
}

// NewIEthCrossChainManagerProxy creates a new instance of IEthCrossChainManagerProxy, bound to a specific deployed contract.
func NewIEthCrossChainManagerProxy(address common.Address, backend bind.ContractBackend) (*IEthCrossChainManagerProxy, error) {
	contract, err := bindIEthCrossChainManagerProxy(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &IEthCrossChainManagerProxy{IEthCrossChainManagerProxyCaller: IEthCrossChainManagerProxyCaller{contract: contract}, IEthCrossChainManagerProxyTransactor: IEthCrossChainManagerProxyTransactor{contract: contract}, IEthCrossChainManagerProxyFilterer: IEthCrossChainManagerProxyFilterer{contract: contract}}, nil
}

// NewIEthCrossChainManagerProxyCaller creates a new read-only instance of IEthCrossChainManagerProxy, bound to a specific deployed contract.
func NewIEthCrossChainManagerProxyCaller(address common.Address, caller bind.ContractCaller) (*IEthCrossChainManagerProxyCaller, error) {
	contract, err := bindIEthCrossChainManagerProxy(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &IEthCrossChainManagerProxyCaller{contract: contract}, nil
}

// NewIEthCrossChainManagerProxyTransactor creates a new write-only instance of IEthCrossChainManagerProxy, bound to a specific deployed contract.
func NewIEthCrossChainManagerProxyTransactor(address common.Address, transactor bind.ContractTransactor) (*IEthCrossChainManagerProxyTransactor, error) {
	contract, err := bindIEthCrossChainManagerProxy(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &IEthCrossChainManagerProxyTransactor{contract: contract}, nil
}

// NewIEthCrossChainManagerProxyFilterer creates a new log filterer instance of IEthCrossChainManagerProxy, bound to a specific deployed contract.
func NewIEthCrossChainManagerProxyFilterer(address common.Address, filterer bind.ContractFilterer) (*IEthCrossChainManagerProxyFilterer, error) {
	contract, err := bindIEthCrossChainManagerProxy(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &IEthCrossChainManagerProxyFilterer{contract: contract}, nil
}

// bindIEthCrossChainManagerProxy binds a generic wrapper to an already deployed contract.
func bindIEthCrossChainManagerProxy(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(IEthCrossChainManagerProxyABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _IEthCrossChainManagerProxy.Contract.IEthCrossChainManagerProxyCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _IEthCrossChainManagerProxy.Contract.IEthCrossChainManagerProxyTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _IEthCrossChainManagerProxy.Contract.IEthCrossChainManagerProxyTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _IEthCrossChainManagerProxy.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _IEthCrossChainManagerProxy.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _IEthCrossChainManagerProxy.Contract.contract.Transact(opts, method, params...)
}

// GetEthCrossChainManager is a free data retrieval call binding the contract method 0x483bf041.
//
// Solidity: function getEthCrossChainManager() constant returns(address)
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyCaller) GetEthCrossChainManager(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _IEthCrossChainManagerProxy.contract.Call(opts, out, "getEthCrossChainManager")
	return *ret0, err
}

// GetEthCrossChainManager is a free data retrieval call binding the contract method 0x483bf041.
//
// Solidity: function getEthCrossChainManager() constant returns(address)
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxySession) GetEthCrossChainManager() (common.Address, error) {
	return _IEthCrossChainManagerProxy.Contract.GetEthCrossChainManager(&_IEthCrossChainManagerProxy.CallOpts)
}

// GetEthCrossChainManager is a free data retrieval call binding the contract method 0x483bf041.
//
// Solidity: function getEthCrossChainManager() constant returns(address)
func (_IEthCrossChainManagerProxy *IEthCrossChainManagerProxyCallerSession) GetEthCrossChainManager() (common.Address, error) {
	return _IEthCrossChainManagerProxy.Contract.GetEthCrossChainManager(&_IEthCrossChainManagerProxy.CallOpts)
}

// IUpgradableECCMABI is the input ABI used to generate the binding from.
const IUpgradableECCMABI = "[{\"constant\":false,\"inputs\":[],\"name\":\"unpause\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"isOwner\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"upgradeToNew\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"pause\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// IUpgradableECCMFuncSigs maps the 4-byte function signature to its string representation.
var IUpgradableECCMFuncSigs = map[string]string{
	"ede8e529": "isOwner()",
	"f4fbb0c8": "pause()",
	"d4bc9601": "paused()",
	"63c37526": "unpause()",
	"f4e614d2": "upgradeToNew(address)",
}

// IUpgradableECCM is an auto generated Go binding around a Solidity contract.
type IUpgradableECCM struct {
	IUpgradableECCMCaller     // Read-only binding to the contract
	IUpgradableECCMTransactor // Write-only binding to the contract
	IUpgradableECCMFilterer   // Log filterer for contract events
}

// IUpgradableECCMCaller is an auto generated read-only Go binding around a Solidity contract.
type IUpgradableECCMCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IUpgradableECCMTransactor is an auto generated write-only Go binding around a Solidity contract.
type IUpgradableECCMTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IUpgradableECCMFilterer is an auto generated log filtering Go binding around a Solidity contract events.
type IUpgradableECCMFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IUpgradableECCMSession is an auto generated Go binding around a Solidity contract,
// with pre-set call and transact options.
type IUpgradableECCMSession struct {
	Contract     *IUpgradableECCM  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// IUpgradableECCMCallerSession is an auto generated read-only Go binding around a Solidity contract,
// with pre-set call options.
type IUpgradableECCMCallerSession struct {
	Contract *IUpgradableECCMCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// IUpgradableECCMTransactorSession is an auto generated write-only Go binding around a Solidity contract,
// with pre-set transact options.
type IUpgradableECCMTransactorSession struct {
	Contract     *IUpgradableECCMTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// IUpgradableECCMRaw is an auto generated low-level Go binding around a Solidity contract.
type IUpgradableECCMRaw struct {
	Contract *IUpgradableECCM // Generic contract binding to access the raw methods on
}

// IUpgradableECCMCallerRaw is an auto generated low-level read-only Go binding around a Solidity contract.
type IUpgradableECCMCallerRaw struct {
	Contract *IUpgradableECCMCaller // Generic read-only contract binding to access the raw methods on
}

// IUpgradableECCMTransactorRaw is an auto generated low-level write-only Go binding around a Solidity contract.
type IUpgradableECCMTransactorRaw struct {
	Contract *IUpgradableECCMTransactor // Generic write-only contract binding to access the raw methods on
}

// NewIUpgradableECCM creates a new instance of IUpgradableECCM, bound to a specific deployed contract.
func NewIUpgradableECCM(address common.Address, backend bind.ContractBackend) (*IUpgradableECCM, error) {
	contract, err := bindIUpgradableECCM(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &IUpgradableECCM{IUpgradableECCMCaller: IUpgradableECCMCaller{contract: contract}, IUpgradableECCMTransactor: IUpgradableECCMTransactor{contract: contract}, IUpgradableECCMFilterer: IUpgradableECCMFilterer{contract: contract}}, nil
}

// NewIUpgradableECCMCaller creates a new read-only instance of IUpgradableECCM, bound to a specific deployed contract.
func NewIUpgradableECCMCaller(address common.Address, caller bind.ContractCaller) (*IUpgradableECCMCaller, error) {
	contract, err := bindIUpgradableECCM(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &IUpgradableECCMCaller{contract: contract}, nil
}

// NewIUpgradableECCMTransactor creates a new write-only instance of IUpgradableECCM, bound to a specific deployed contract.
func NewIUpgradableECCMTransactor(address common.Address, transactor bind.ContractTransactor) (*IUpgradableECCMTransactor, error) {
	contract, err := bindIUpgradableECCM(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &IUpgradableECCMTransactor{contract: contract}, nil
}

// NewIUpgradableECCMFilterer creates a new log filterer instance of IUpgradableECCM, bound to a specific deployed contract.
func NewIUpgradableECCMFilterer(address common.Address, filterer bind.ContractFilterer) (*IUpgradableECCMFilterer, error) {
	contract, err := bindIUpgradableECCM(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &IUpgradableECCMFilterer{contract: contract}, nil
}

// bindIUpgradableECCM binds a generic wrapper to an already deployed contract.
func bindIUpgradableECCM(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(IUpgradableECCMABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IUpgradableECCM *IUpgradableECCMRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _IUpgradableECCM.Contract.IUpgradableECCMCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IUpgradableECCM *IUpgradableECCMRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.IUpgradableECCMTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IUpgradableECCM *IUpgradableECCMRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.IUpgradableECCMTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IUpgradableECCM *IUpgradableECCMCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _IUpgradableECCM.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IUpgradableECCM *IUpgradableECCMTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IUpgradableECCM *IUpgradableECCMTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.contract.Transact(opts, method, params...)
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_IUpgradableECCM *IUpgradableECCMCaller) IsOwner(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _IUpgradableECCM.contract.Call(opts, out, "isOwner")
	return *ret0, err
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_IUpgradableECCM *IUpgradableECCMSession) IsOwner() (bool, error) {
	return _IUpgradableECCM.Contract.IsOwner(&_IUpgradableECCM.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_IUpgradableECCM *IUpgradableECCMCallerSession) IsOwner() (bool, error) {
	return _IUpgradableECCM.Contract.IsOwner(&_IUpgradableECCM.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_IUpgradableECCM *IUpgradableECCMCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _IUpgradableECCM.contract.Call(opts, out, "paused")
	return *ret0, err
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_IUpgradableECCM *IUpgradableECCMSession) Paused() (bool, error) {
	return _IUpgradableECCM.Contract.Paused(&_IUpgradableECCM.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_IUpgradableECCM *IUpgradableECCMCallerSession) Paused() (bool, error) {
	return _IUpgradableECCM.Contract.Paused(&_IUpgradableECCM.CallOpts)
}

// Pause is a paid mutator transaction binding the contract method 0xf4fbb0c8.
//
// Solidity: function pause() returns(bool)
func (_IUpgradableECCM *IUpgradableECCMTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.contract.Transact(opts, "pause")
}

func (_IUpgradableECCM *IUpgradableECCMTransactor) AsyncPause(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IUpgradableECCM.contract.AsyncTransact(opts, handler, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0xf4fbb0c8.
//
// Solidity: function pause() returns(bool)
func (_IUpgradableECCM *IUpgradableECCMSession) Pause() (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.Pause(&_IUpgradableECCM.TransactOpts)
}

func (_IUpgradableECCM *IUpgradableECCMSession) AsyncPause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _IUpgradableECCM.Contract.AsyncPause(handler, &_IUpgradableECCM.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0xf4fbb0c8.
//
// Solidity: function pause() returns(bool)
func (_IUpgradableECCM *IUpgradableECCMTransactorSession) Pause() (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.Pause(&_IUpgradableECCM.TransactOpts)
}

func (_IUpgradableECCM *IUpgradableECCMTransactorSession) AsyncPause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _IUpgradableECCM.Contract.AsyncPause(handler, &_IUpgradableECCM.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x63c37526.
//
// Solidity: function unpause() returns(bool)
func (_IUpgradableECCM *IUpgradableECCMTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.contract.Transact(opts, "unpause")
}

func (_IUpgradableECCM *IUpgradableECCMTransactor) AsyncUnpause(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IUpgradableECCM.contract.AsyncTransact(opts, handler, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x63c37526.
//
// Solidity: function unpause() returns(bool)
func (_IUpgradableECCM *IUpgradableECCMSession) Unpause() (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.Unpause(&_IUpgradableECCM.TransactOpts)
}

func (_IUpgradableECCM *IUpgradableECCMSession) AsyncUnpause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _IUpgradableECCM.Contract.AsyncUnpause(handler, &_IUpgradableECCM.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x63c37526.
//
// Solidity: function unpause() returns(bool)
func (_IUpgradableECCM *IUpgradableECCMTransactorSession) Unpause() (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.Unpause(&_IUpgradableECCM.TransactOpts)
}

func (_IUpgradableECCM *IUpgradableECCMTransactorSession) AsyncUnpause(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _IUpgradableECCM.Contract.AsyncUnpause(handler, &_IUpgradableECCM.TransactOpts)
}

// UpgradeToNew is a paid mutator transaction binding the contract method 0xf4e614d2.
//
// Solidity: function upgradeToNew(address ) returns(bool)
func (_IUpgradableECCM *IUpgradableECCMTransactor) UpgradeToNew(opts *bind.TransactOpts, arg0 common.Address) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.contract.Transact(opts, "upgradeToNew", arg0)
}

func (_IUpgradableECCM *IUpgradableECCMTransactor) AsyncUpgradeToNew(handler func(*types.Receipt, error), opts *bind.TransactOpts, arg0 common.Address) (*types.Transaction, error) {
	return _IUpgradableECCM.contract.AsyncTransact(opts, handler, "upgradeToNew", arg0)
}

// UpgradeToNew is a paid mutator transaction binding the contract method 0xf4e614d2.
//
// Solidity: function upgradeToNew(address ) returns(bool)
func (_IUpgradableECCM *IUpgradableECCMSession) UpgradeToNew(arg0 common.Address) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.UpgradeToNew(&_IUpgradableECCM.TransactOpts, arg0)
}

func (_IUpgradableECCM *IUpgradableECCMSession) AsyncUpgradeToNew(handler func(*types.Receipt, error), arg0 common.Address) (*types.Transaction, error) {
	return _IUpgradableECCM.Contract.AsyncUpgradeToNew(handler, &_IUpgradableECCM.TransactOpts, arg0)
}

// UpgradeToNew is a paid mutator transaction binding the contract method 0xf4e614d2.
//
// Solidity: function upgradeToNew(address ) returns(bool)
func (_IUpgradableECCM *IUpgradableECCMTransactorSession) UpgradeToNew(arg0 common.Address) (*types.Transaction, *types.Receipt, error) {
	return _IUpgradableECCM.Contract.UpgradeToNew(&_IUpgradableECCM.TransactOpts, arg0)
}

func (_IUpgradableECCM *IUpgradableECCMTransactorSession) AsyncUpgradeToNew(handler func(*types.Receipt, error), arg0 common.Address) (*types.Transaction, error) {
	return _IUpgradableECCM.Contract.AsyncUpgradeToNew(handler, &_IUpgradableECCM.TransactOpts, arg0)
}

// OwnableABI is the input ABI used to generate the binding from.
const OwnableABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"isOwner\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"}]"

// OwnableFuncSigs maps the 4-byte function signature to its string representation.
var OwnableFuncSigs = map[string]string{
	"ede8e529": "isOwner()",
	"5089e2c8": "owner()",
	"d86e29e2": "renounceOwnership()",
	"16cad12a": "transferOwnership(address)",
}

// Ownable is an auto generated Go binding around a Solidity contract.
type Ownable struct {
	OwnableCaller     // Read-only binding to the contract
	OwnableTransactor // Write-only binding to the contract
	OwnableFilterer   // Log filterer for contract events
}

// OwnableCaller is an auto generated read-only Go binding around a Solidity contract.
type OwnableCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnableTransactor is an auto generated write-only Go binding around a Solidity contract.
type OwnableTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnableFilterer is an auto generated log filtering Go binding around a Solidity contract events.
type OwnableFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnableSession is an auto generated Go binding around a Solidity contract,
// with pre-set call and transact options.
type OwnableSession struct {
	Contract     *Ownable          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// OwnableCallerSession is an auto generated read-only Go binding around a Solidity contract,
// with pre-set call options.
type OwnableCallerSession struct {
	Contract *OwnableCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// OwnableTransactorSession is an auto generated write-only Go binding around a Solidity contract,
// with pre-set transact options.
type OwnableTransactorSession struct {
	Contract     *OwnableTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// OwnableRaw is an auto generated low-level Go binding around a Solidity contract.
type OwnableRaw struct {
	Contract *Ownable // Generic contract binding to access the raw methods on
}

// OwnableCallerRaw is an auto generated low-level read-only Go binding around a Solidity contract.
type OwnableCallerRaw struct {
	Contract *OwnableCaller // Generic read-only contract binding to access the raw methods on
}

// OwnableTransactorRaw is an auto generated low-level write-only Go binding around a Solidity contract.
type OwnableTransactorRaw struct {
	Contract *OwnableTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOwnable creates a new instance of Ownable, bound to a specific deployed contract.
func NewOwnable(address common.Address, backend bind.ContractBackend) (*Ownable, error) {
	contract, err := bindOwnable(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Ownable{OwnableCaller: OwnableCaller{contract: contract}, OwnableTransactor: OwnableTransactor{contract: contract}, OwnableFilterer: OwnableFilterer{contract: contract}}, nil
}

// NewOwnableCaller creates a new read-only instance of Ownable, bound to a specific deployed contract.
func NewOwnableCaller(address common.Address, caller bind.ContractCaller) (*OwnableCaller, error) {
	contract, err := bindOwnable(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &OwnableCaller{contract: contract}, nil
}

// NewOwnableTransactor creates a new write-only instance of Ownable, bound to a specific deployed contract.
func NewOwnableTransactor(address common.Address, transactor bind.ContractTransactor) (*OwnableTransactor, error) {
	contract, err := bindOwnable(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &OwnableTransactor{contract: contract}, nil
}

// NewOwnableFilterer creates a new log filterer instance of Ownable, bound to a specific deployed contract.
func NewOwnableFilterer(address common.Address, filterer bind.ContractFilterer) (*OwnableFilterer, error) {
	contract, err := bindOwnable(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &OwnableFilterer{contract: contract}, nil
}

// bindOwnable binds a generic wrapper to an already deployed contract.
func bindOwnable(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(OwnableABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Ownable *OwnableRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Ownable.Contract.OwnableCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Ownable *OwnableRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.OwnableTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Ownable *OwnableRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.OwnableTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Ownable *OwnableCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Ownable.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Ownable *OwnableTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Ownable *OwnableTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.contract.Transact(opts, method, params...)
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_Ownable *OwnableCaller) IsOwner(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _Ownable.contract.Call(opts, out, "isOwner")
	return *ret0, err
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_Ownable *OwnableSession) IsOwner() (bool, error) {
	return _Ownable.Contract.IsOwner(&_Ownable.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0xede8e529.
//
// Solidity: function isOwner() constant returns(bool)
func (_Ownable *OwnableCallerSession) IsOwner() (bool, error) {
	return _Ownable.Contract.IsOwner(&_Ownable.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x5089e2c8.
//
// Solidity: function owner() constant returns(address)
func (_Ownable *OwnableCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Ownable.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x5089e2c8.
//
// Solidity: function owner() constant returns(address)
func (_Ownable *OwnableSession) Owner() (common.Address, error) {
	return _Ownable.Contract.Owner(&_Ownable.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x5089e2c8.
//
// Solidity: function owner() constant returns(address)
func (_Ownable *OwnableCallerSession) Owner() (common.Address, error) {
	return _Ownable.Contract.Owner(&_Ownable.CallOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0xd86e29e2.
//
// Solidity: function renounceOwnership() returns()
func (_Ownable *OwnableTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.contract.Transact(opts, "renounceOwnership")
}

func (_Ownable *OwnableTransactor) AsyncRenounceOwnership(handler func(*types.Receipt, error), opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Ownable.contract.AsyncTransact(opts, handler, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0xd86e29e2.
//
// Solidity: function renounceOwnership() returns()
func (_Ownable *OwnableSession) RenounceOwnership() (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.RenounceOwnership(&_Ownable.TransactOpts)
}

func (_Ownable *OwnableSession) AsyncRenounceOwnership(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _Ownable.Contract.AsyncRenounceOwnership(handler, &_Ownable.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0xd86e29e2.
//
// Solidity: function renounceOwnership() returns()
func (_Ownable *OwnableTransactorSession) RenounceOwnership() (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.RenounceOwnership(&_Ownable.TransactOpts)
}

func (_Ownable *OwnableTransactorSession) AsyncRenounceOwnership(handler func(*types.Receipt, error)) (*types.Transaction, error) {
	return _Ownable.Contract.AsyncRenounceOwnership(handler, &_Ownable.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x16cad12a.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Ownable *OwnableTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.contract.Transact(opts, "transferOwnership", newOwner)
}

func (_Ownable *OwnableTransactor) AsyncTransferOwnership(handler func(*types.Receipt, error), opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Ownable.contract.AsyncTransact(opts, handler, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x16cad12a.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Ownable *OwnableSession) TransferOwnership(newOwner common.Address) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.TransferOwnership(&_Ownable.TransactOpts, newOwner)
}

func (_Ownable *OwnableSession) AsyncTransferOwnership(handler func(*types.Receipt, error), newOwner common.Address) (*types.Transaction, error) {
	return _Ownable.Contract.AsyncTransferOwnership(handler, &_Ownable.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0x16cad12a.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Ownable *OwnableTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, *types.Receipt, error) {
	return _Ownable.Contract.TransferOwnership(&_Ownable.TransactOpts, newOwner)
}

func (_Ownable *OwnableTransactorSession) AsyncTransferOwnership(handler func(*types.Receipt, error), newOwner common.Address) (*types.Transaction, error) {
	return _Ownable.Contract.AsyncTransferOwnership(handler, &_Ownable.TransactOpts, newOwner)
}

// OwnableOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the Ownable contract.
type OwnableOwnershipTransferredIterator struct {
	Event *OwnableOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *OwnableOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(OwnableOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(OwnableOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *OwnableOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *OwnableOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// OwnableOwnershipTransferred represents a OwnershipTransferred event raised by the Ownable contract.
type OwnableOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x000000000000000000000000000000000000000000000000000000005c7c30d4.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Ownable *OwnableFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*OwnableOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Ownable.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &OwnableOwnershipTransferredIterator{contract: _Ownable.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x000000000000000000000000000000000000000000000000000000005c7c30d4.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Ownable *OwnableFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *OwnableOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Ownable.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(OwnableOwnershipTransferred)
				if err := _Ownable.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x000000000000000000000000000000000000000000000000000000005c7c30d4.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Ownable *OwnableFilterer) ParseOwnershipTransferred(log types.Log) (*OwnableOwnershipTransferred, error) {
	event := new(OwnableOwnershipTransferred)
	if err := _Ownable.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	return event, nil
}

// PausableABI is the input ABI used to generate the binding from.
const PausableABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Paused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Unpaused\",\"type\":\"event\"}]"

// PausableFuncSigs maps the 4-byte function signature to its string representation.
var PausableFuncSigs = map[string]string{
	"d4bc9601": "paused()",
}

// Pausable is an auto generated Go binding around a Solidity contract.
type Pausable struct {
	PausableCaller     // Read-only binding to the contract
	PausableTransactor // Write-only binding to the contract
	PausableFilterer   // Log filterer for contract events
}

// PausableCaller is an auto generated read-only Go binding around a Solidity contract.
type PausableCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PausableTransactor is an auto generated write-only Go binding around a Solidity contract.
type PausableTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PausableFilterer is an auto generated log filtering Go binding around a Solidity contract events.
type PausableFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PausableSession is an auto generated Go binding around a Solidity contract,
// with pre-set call and transact options.
type PausableSession struct {
	Contract     *Pausable         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// PausableCallerSession is an auto generated read-only Go binding around a Solidity contract,
// with pre-set call options.
type PausableCallerSession struct {
	Contract *PausableCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// PausableTransactorSession is an auto generated write-only Go binding around a Solidity contract,
// with pre-set transact options.
type PausableTransactorSession struct {
	Contract     *PausableTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// PausableRaw is an auto generated low-level Go binding around a Solidity contract.
type PausableRaw struct {
	Contract *Pausable // Generic contract binding to access the raw methods on
}

// PausableCallerRaw is an auto generated low-level read-only Go binding around a Solidity contract.
type PausableCallerRaw struct {
	Contract *PausableCaller // Generic read-only contract binding to access the raw methods on
}

// PausableTransactorRaw is an auto generated low-level write-only Go binding around a Solidity contract.
type PausableTransactorRaw struct {
	Contract *PausableTransactor // Generic write-only contract binding to access the raw methods on
}

// NewPausable creates a new instance of Pausable, bound to a specific deployed contract.
func NewPausable(address common.Address, backend bind.ContractBackend) (*Pausable, error) {
	contract, err := bindPausable(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Pausable{PausableCaller: PausableCaller{contract: contract}, PausableTransactor: PausableTransactor{contract: contract}, PausableFilterer: PausableFilterer{contract: contract}}, nil
}

// NewPausableCaller creates a new read-only instance of Pausable, bound to a specific deployed contract.
func NewPausableCaller(address common.Address, caller bind.ContractCaller) (*PausableCaller, error) {
	contract, err := bindPausable(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PausableCaller{contract: contract}, nil
}

// NewPausableTransactor creates a new write-only instance of Pausable, bound to a specific deployed contract.
func NewPausableTransactor(address common.Address, transactor bind.ContractTransactor) (*PausableTransactor, error) {
	contract, err := bindPausable(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &PausableTransactor{contract: contract}, nil
}

// NewPausableFilterer creates a new log filterer instance of Pausable, bound to a specific deployed contract.
func NewPausableFilterer(address common.Address, filterer bind.ContractFilterer) (*PausableFilterer, error) {
	contract, err := bindPausable(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &PausableFilterer{contract: contract}, nil
}

// bindPausable binds a generic wrapper to an already deployed contract.
func bindPausable(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(PausableABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Pausable *PausableRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Pausable.Contract.PausableCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Pausable *PausableRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Pausable.Contract.PausableTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Pausable *PausableRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _Pausable.Contract.PausableTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Pausable *PausableCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Pausable.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Pausable *PausableTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return _Pausable.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Pausable *PausableTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	return _Pausable.Contract.contract.Transact(opts, method, params...)
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_Pausable *PausableCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _Pausable.contract.Call(opts, out, "paused")
	return *ret0, err
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_Pausable *PausableSession) Paused() (bool, error) {
	return _Pausable.Contract.Paused(&_Pausable.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0xd4bc9601.
//
// Solidity: function paused() constant returns(bool)
func (_Pausable *PausableCallerSession) Paused() (bool, error) {
	return _Pausable.Contract.Paused(&_Pausable.CallOpts)
}

// PausablePausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the Pausable contract.
type PausablePausedIterator struct {
	Event *PausablePaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *PausablePausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PausablePaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(PausablePaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *PausablePausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PausablePausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PausablePaused represents a Paused event raised by the Pausable contract.
type PausablePaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x000000000000000000000000000000000000000000000000000000003572985a.
//
// Solidity: event Paused(address account)
func (_Pausable *PausableFilterer) FilterPaused(opts *bind.FilterOpts) (*PausablePausedIterator, error) {

	logs, sub, err := _Pausable.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &PausablePausedIterator{contract: _Pausable.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x000000000000000000000000000000000000000000000000000000003572985a.
//
// Solidity: event Paused(address account)
func (_Pausable *PausableFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *PausablePaused) (event.Subscription, error) {

	logs, sub, err := _Pausable.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PausablePaused)
				if err := _Pausable.contract.UnpackLog(event, "Paused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x000000000000000000000000000000000000000000000000000000003572985a.
//
// Solidity: event Paused(address account)
func (_Pausable *PausableFilterer) ParsePaused(log types.Log) (*PausablePaused, error) {
	event := new(PausablePaused)
	if err := _Pausable.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	return event, nil
}

// PausableUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the Pausable contract.
type PausableUnpausedIterator struct {
	Event *PausableUnpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *PausableUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PausableUnpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(PausableUnpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *PausableUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PausableUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PausableUnpaused represents a Unpaused event raised by the Pausable contract.
type PausableUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x0000000000000000000000000000000000000000000000000000000044693cad.
//
// Solidity: event Unpaused(address account)
func (_Pausable *PausableFilterer) FilterUnpaused(opts *bind.FilterOpts) (*PausableUnpausedIterator, error) {

	logs, sub, err := _Pausable.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &PausableUnpausedIterator{contract: _Pausable.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x0000000000000000000000000000000000000000000000000000000044693cad.
//
// Solidity: event Unpaused(address account)
func (_Pausable *PausableFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *PausableUnpaused) (event.Subscription, error) {

	logs, sub, err := _Pausable.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PausableUnpaused)
				if err := _Pausable.contract.UnpackLog(event, "Unpaused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x0000000000000000000000000000000000000000000000000000000044693cad.
//
// Solidity: event Unpaused(address account)
func (_Pausable *PausableFilterer) ParseUnpaused(log types.Log) (*PausableUnpaused, error) {
	event := new(PausableUnpaused)
	if err := _Pausable.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	return event, nil
}

package ycsbcosmoskvstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	ctx "github.com/cosmos/cosmos-sdk/client/tx"
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	auth "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/vittoriocapocasale/kvstore/x/kvstore/types"
	"golang.org/x/crypto/ripemd160"
	"google.golang.org/grpc"

	"github.com/cosmos/btcutil/bech32"
	"github.com/gorilla/websocket"
)

func main() {
	k := NewTMConnect("localhost:26657", "/websocket")
	h := NewMyHandler()
	k.BlockSubscribe(h)
	time.Sleep(10 * time.Second)
	k.Close()
}

func main2() {
	key := "4478aaf49852e3a29a80779e5a905d9881a9011a3ed16760db9ce513c00e9798"
	//key := "1bd467d4ec82a18e649e4ae39acc1b7e3797b7a92bd2c6a8874cf20581103036"
	acc := NewAccount(key, "cosmos", 4, 0)
	if acc == nil {
		panic("nil account")
	}

	conn, err := NewConnection("127.0.0.1:9090")
	defer conn.Close()
	acc.QueryInfo(conn)
	if err != nil {
		panic(err)
	}
	querier := types.NewQueryClient(conn)

	//txconf := PrepareTransaction()
	//msg := types.NewMsgWriteKey(acc.GetAddress("cosmos"), "Hello", "Won")
	msg2 := types.NewMsgWriteKey(acc.GetAddress(), "Hello", "world")
	err = BuildSignBroadcast("test-chain-95APpL", acc, conn, []sdk.Msg{msg2})
	if err != nil {
		panic(err)
	}
	time.Sleep(10 * time.Second)
	req := &types.QueryGetValueRequest{Key: "Hello"}
	resp, err := querier.GetValue(context.Background(), req)
	if err != nil {
		panic(err)
	}
	fmt.Println("Key hello has value: ", len(resp.GetValue()), resp.GetValue())

	acc.QueryInfo(conn)
	if err != nil {
		panic(err)
	}
	msg3 := types.NewMsgWriteKey(acc.GetAddress(), "Hello", "work")
	err = BuildSignBroadcast("test-chain-95APpL", acc, conn, []sdk.Msg{msg3})
	if err != nil {
		panic(err)
	}
	time.Sleep(10 * time.Second)
	resp, err = querier.GetValue(context.Background(), req)
	if err != nil {
		panic(err)
	}
	fmt.Println("Key hello has value: ", len(resp.GetValue()), resp.GetValue())
}

func publicKeyToAddress(addressPrefix string, pubKeyBytes []byte) string {

	// Hash pubKeyBytes as: RIPEMD160(SHA256(public_key_bytes))
	pubKeySha256Hash := sha256.Sum256(pubKeyBytes)
	ripemd160hash := ripemd160.New()
	ripemd160hash.Write(pubKeySha256Hash[:])
	addressBytes := ripemd160hash.Sum(nil)

	// Convert addressBytes into a bech32 string
	address := toBech32(string(addressPrefix), addressBytes)

	return address
}

// Code courtesy: https://github.com/cosmos/cosmos-sdk/blob/90c9c9a9eb4676d05d3f4b89d9a907bd3db8194f/types/bech32/bech32.go#L10
func toBech32(addrPrefix string, addrBytes []byte) string {
	converted, err := bech32.ConvertBits(addrBytes, 8, 5, true)
	if err != nil {
		panic(err)
	}

	addr, err := bech32.Encode(addrPrefix, converted)
	if err != nil {
		panic(err)
	}

	return addr
}

type Account struct {
	PrKey  cryptotypes.PrivKey
	prefix string
	accNum uint64
	accSeq uint64
}

func NewAccount(hexKey string, prefix string, accNum uint64, accSeq uint64) *Account {
	data, err := hex.DecodeString(hexKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var key cryptotypes.PrivKey = &secp256k1.PrivKey{Key: data}
	acc := &Account{key, prefix, accNum, accSeq}
	return acc
}

func (acc *Account) IncreaseAccSeq() {
	acc.accSeq = acc.accSeq + 1
}

func (acc *Account) GetAccSeq() uint64 {
	return acc.accSeq
}

func (acc *Account) GetAccNum() uint64 {
	return acc.accNum
}

func (acc *Account) GetPrKey() cryptotypes.PrivKey {
	return acc.PrKey
}

func (acc *Account) GetPubKey() cryptotypes.PubKey {
	return acc.PrKey.PubKey()
}
func (acc *Account) GetAddress() string {
	return publicKeyToAddress(acc.prefix, acc.PrKey.PubKey().Bytes())
}

func (acc *Account) QueryInfo(conn *grpc.ClientConn) {
	resp, err := authtypes.NewQueryClient(conn).Account(context.Background(), &authtypes.QueryAccountRequest{Address: acc.GetAddress()})
	if err != nil {
		panic(err)
	}
	a := authtypes.BaseAccount{}
	a.Unmarshal(resp.GetAccount().GetValue())
	acc.accNum = a.AccountNumber
	acc.accSeq = a.Sequence
}

func NewConnection(url string) (*grpc.ClientConn, error) {
	conn, err := grpc.Dial(url, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func BuildSignBroadcast(chainID string, acc *Account, conn *grpc.ClientConn, msgs []sdk.Msg) error {
	txConfig := PrepareTransaction()
	txBuilder, err := BuildTransaction(txConfig, msgs)
	if err != nil {
		return err
	}
	err = SignTransaction(chainID, acc, txConfig, txBuilder)
	if err != nil {
		return err
	}
	return SendTransactionAsync(conn, txConfig, txBuilder)
}

func PrepareTransaction() *client.TxConfig {
	txConfig := auth.NewTxConfig(types.ModuleCdc, []signing.SignMode{signing.SignMode_SIGN_MODE_DIRECT})
	return &txConfig
}

func BuildTransaction(txConfig *client.TxConfig, msgs []sdk.Msg) (*client.TxBuilder, error) {
	txBuilder := (*txConfig).NewTxBuilder()
	err := txBuilder.SetMsgs(msgs...)
	if err != nil {
		return nil, err
	}
	//txBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewCoin("atom", sdk.NewIntFromUint64(uint64(1000000*len(msgs))))))
	txBuilder.SetGasLimit(200000 * uint64(len(msgs)))
	return &txBuilder, nil
}

func SignTransaction(chainID string, acc *Account, txConfig *client.TxConfig, txBuilder *client.TxBuilder) error {
	pubKey := acc.GetPubKey()
	signMode := signing.SignMode_SIGN_MODE_DIRECT

	// For SIGN_MODE_DIRECT, calling SetSignatures calls setSignerInfos on
	// TxBuilder under the hood, and SignerInfos is needed to generated the
	// sign bytes. This is the reason for setting SetSignatures here, with a
	// nil signature.
	//
	// Note: this line is not needed for SIGN_MODE_LEGACY_AMINO, but putting it
	// also doesn't affect its generated sign bytes, so for code's simplicity
	// sake, we put it here.
	var sigsV2 []signing.SignatureV2

	sigData := signing.SingleSignatureData{
		SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
		Signature: nil,
	}
	sig := signing.SignatureV2{
		PubKey:   pubKey,
		Data:     &sigData,
		Sequence: acc.GetAccSeq(),
	}
	sigsV2 = append(sigsV2, sig)
	err := (*txBuilder).SetSignatures(sigsV2...)
	if err != nil {
		return err
	}

	signerData := authsigning.SignerData{
		ChainID:       chainID,
		AccountNumber: acc.GetAccNum(),
		Sequence:      acc.GetAccSeq(),
	}

	signature, err := ctx.SignWithPrivKey(signMode, signerData, *txBuilder, acc.GetPrKey(), *txConfig, acc.GetAccSeq())
	if err != nil {
		return err
	}
	sigsV2 = []signing.SignatureV2{signature}
	return (*txBuilder).SetSignatures(sigsV2...)
}

func SendTransactionAsync(conn *grpc.ClientConn, txConfig *client.TxConfig, txBuilder *client.TxBuilder) error {
	client := tx.NewServiceClient(conn)
	txBytes, err := (*txConfig).TxEncoder()((*txBuilder).GetTx())
	if err != nil {
		return err
	}
	_, err = client.BroadcastTx(context.Background(), &tx.BroadcastTxRequest{
		Mode:    tx.BroadcastMode_BROADCAST_MODE_ASYNC,
		TxBytes: txBytes, // Proto-binary of the signed transaction, see previous step.
	})
	if err != nil {
		return err
	}
	return nil
}

func BuildSign(chainID string, acc *Account, msgs []sdk.Msg) ([]byte, error) {
	txConfig := PrepareTransaction()
	txBuilder, err := BuildTransaction(txConfig, msgs)
	if err != nil {
		return nil, err
	}
	err = SignTransaction(chainID, acc, txConfig, txBuilder)
	if err != nil {
		return nil, err
	}
	txBytes, err := (*txConfig).TxEncoder()((*txBuilder).GetTx())
	if err != nil {
		return nil, err
	}
	return txBytes, nil
}

func SendBytesAsync(conn *grpc.ClientConn, txBytes []byte) error {
	client := tx.NewServiceClient(conn)
	_, err := client.BroadcastTx(context.Background(), &tx.BroadcastTxRequest{
		Mode:    tx.BroadcastMode_BROADCAST_MODE_ASYNC,
		TxBytes: txBytes, // Proto-binary of the signed transaction, see previous step.
	})
	if err != nil {
		return err
	}
	return nil
}

type MyHandler struct{}

func NewMyHandler() *MyHandler {
	return &MyHandler{}
}
func (mh *MyHandler) Handle(msg []byte) {
	fmt.Println(string(msg))
}

type Handler interface {
	Handle([]byte)
}

type TMConn struct {
	hostnport string
	path      string
	conn      *websocket.Conn
	done      chan struct{}
	handler   Handler
}

func NewTMConnect(hostnport string, path string) *TMConn {
	tm := &TMConn{hostnport, path, nil, nil, nil}
	err := tm.connect()
	if err != nil {
		return nil
	}
	return tm
}

func (tm *TMConn) connect() error {
	//tcp://0.0.0.0:26657/websocket
	link := url.URL{Scheme: "ws", Host: tm.hostnport, Path: tm.path}
	c, _, err := websocket.DefaultDialer.Dial(link.String(), nil)
	if err != nil {
		return err
	}
	tm.conn = c
	return nil
}

func (tm *TMConn) BlockSubscribe(handler Handler) error {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "subscribe",
		"id":      1,
		"params":  []string{"tm.event='NewBlock'"},
	}
	// Send the payload as JSON to the server
	tm.handler = handler
	tm.done = make(chan struct{})
	go tm.handleMessage()
	return tm.conn.WriteJSON(payload)
}

func (tm *TMConn) UnsubscribeAll() error {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "unsubscribe_all",
		"id":      1,
	}
	// Send the payload as JSON to the server
	return tm.conn.WriteJSON(payload)
}

func (tm *TMConn) handleMessage() {

	//result>data>value>block>data>txs
	defer close(tm.done)
	for {
		// Read the incoming message from the server
		_, message, err := tm.conn.ReadMessage()
		if err != nil {
			return
		}
		tm.handler.Handle(message)
	}
}

func (tm *TMConn) Close() {
	tm.UnsubscribeAll()
	tm.conn.Close()
	if tm.done != nil {
		<-tm.done
	}
}

type RPCResp struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		Query string `json:"query"`
		Data  struct {
			Type  string `json:"type"`
			Value struct {
				Block struct {
					Header struct {
						Version struct {
							Block string `json:"block"`
						} `json:"version"`
						ChainID     string    `json:"chain_id"`
						Height      string    `json:"height"`
						Time        time.Time `json:"time"`
						LastBlockID struct {
							Hash  string `json:"hash"`
							Parts struct {
								Total int    `json:"total"`
								Hash  string `json:"hash"`
							} `json:"parts"`
						} `json:"last_block_id"`
						LastCommitHash     string `json:"last_commit_hash"`
						DataHash           string `json:"data_hash"`
						ValidatorsHash     string `json:"validators_hash"`
						NextValidatorsHash string `json:"next_validators_hash"`
						ConsensusHash      string `json:"consensus_hash"`
						AppHash            string `json:"app_hash"`
						LastResultsHash    string `json:"last_results_hash"`
						EvidenceHash       string `json:"evidence_hash"`
						ProposerAddress    string `json:"proposer_address"`
					} `json:"header"`
					Data struct {
						Txs []string `json:"txs"`
					} `json:"data"`
					Evidence struct {
						Evidence []interface{} `json:"evidence"`
					} `json:"evidence"`
					LastCommit struct {
						Height  string `json:"height"`
						Round   int    `json:"round"`
						BlockID struct {
							Hash  string `json:"hash"`
							Parts struct {
								Total int    `json:"total"`
								Hash  string `json:"hash"`
							} `json:"parts"`
						} `json:"block_id"`
						Signatures []struct {
							BlockIDFlag      int       `json:"block_id_flag"`
							ValidatorAddress string    `json:"validator_address"`
							Timestamp        time.Time `json:"timestamp"`
							Signature        string    `json:"signature"`
						} `json:"signatures"`
					} `json:"last_commit"`
				} `json:"block"`
				ResultBeginBlock struct {
					Events []struct {
						Type       string `json:"type"`
						Attributes []struct {
							Key   string `json:"key"`
							Value string `json:"value"`
							Index bool   `json:"index"`
						} `json:"attributes"`
					} `json:"events"`
				} `json:"result_begin_block"`
				ResultEndBlock struct {
					ValidatorUpdates      []interface{} `json:"validator_updates"`
					ConsensusParamUpdates struct {
						Block struct {
							MaxBytes string `json:"max_bytes"`
							MaxGas   string `json:"max_gas"`
						} `json:"block"`
						Evidence struct {
							MaxAgeNumBlocks string `json:"max_age_num_blocks"`
							MaxAgeDuration  string `json:"max_age_duration"`
							MaxBytes        string `json:"max_bytes"`
						} `json:"evidence"`
						Validator struct {
							PubKeyTypes []string `json:"pub_key_types"`
						} `json:"validator"`
					} `json:"consensus_param_updates"`
					Events []interface{} `json:"events"`
				} `json:"result_end_block"`
			} `json:"value"`
		} `json:"data"`
		Events struct {
			CoinReceivedAmount      []string `json:"coin_received.amount"`
			CoinSpentSpender        []string `json:"coin_spent.spender"`
			TransferAmount          []string `json:"transfer.amount"`
			MintInflation           []string `json:"mint.inflation"`
			MintAnnualProvisions    []string `json:"mint.annual_provisions"`
			CoinbaseMinter          []string `json:"coinbase.minter"`
			MessageSender           []string `json:"message.sender"`
			MintBondedRatio         []string `json:"mint.bonded_ratio"`
			MintAmount              []string `json:"mint.amount"`
			CommissionAmount        []string `json:"commission.amount"`
			CommissionValidator     []string `json:"commission.validator"`
			TmEvent                 []string `json:"tm.event"`
			CoinbaseAmount          []string `json:"coinbase.amount"`
			CoinSpentAmount         []string `json:"coin_spent.amount"`
			TransferRecipient       []string `json:"transfer.recipient"`
			RewardsAmount           []string `json:"rewards.amount"`
			RewardsValidator        []string `json:"rewards.validator"`
			CoinReceivedReceiver    []string `json:"coin_received.receiver"`
			TransferSender          []string `json:"transfer.sender"`
			ProposerRewardAmount    []string `json:"proposer_reward.amount"`
			ProposerRewardValidator []string `json:"proposer_reward.validator"`
		} `json:"events"`
	} `json:"result"`
}

func ParseAccounts(file string) []string {
	// Open our jsonFile
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer jsonFile.Close()
	ret := make([]string, 0)
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &ret)
	return ret
}

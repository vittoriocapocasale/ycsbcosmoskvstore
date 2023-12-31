package ycsbcosmoskvstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/magiconair/properties"
	"github.com/pingcap/go-ycsb/pkg/ycsb"
	"github.com/vittoriocapocasale/kvstore/x/kvstore/types"
	"google.golang.org/grpc"
)

func init() {
	ycsb.RegisterDBCreator("kvstore", kvCretor{})
}

type kvCretor struct{}

func (kvCretor) Create(p *properties.Properties) (ycsb.DB, error) {
	keyFile, ok := p.Get("keyFile") //"/home/vittorio/workspace/cosmos/testing/coordinator/project/sender/ycsb/db/kvstore/keys.json"
	if !ok {
		panic("Plese, provide keyFile")
	}
	memPoolSizeS, ok := p.Get("memPoolSize") //5000
	if !ok {
		panic("Plese, provide memPoolSize")
	}
	memPoolSize, err := strconv.Atoi(memPoolSizeS)
	if err != nil {
		panic("Plese, provide valid memPoolSize")
	}
	hostnport, ok := p.Get("tmHostnPort") //localhost:26657"
	if !ok {
		panic("Plese, provide tmHostnPort")
	}
	path, ok := p.Get("tmPath") //"/websocket"
	if !ok {
		panic("Plese, provide tmPath")
	}
	endpointsString, ok := p.Get("grpcEndpoints") //[]string{"127.0.0.1:9090", "127.0.0.1:9090", "127.0.0.1:9090", "127.0.0.1:9090"}
	if !ok {
		panic("Plese, provide grpcEndpoints")
	}
	endpoints := strings.Split(endpointsString, ",")

	freeSlots := make(chan bool, memPoolSize)
	for i := 0; i < memPoolSize; i++ {
		freeSlots <- true
	}

	var grpcConn *grpc.ClientConn
	grpcs := make(chan *grpc.ClientConn, len(endpoints))
	for i := 0; i < len(endpoints); i++ {
		conn, err := NewConnection(endpoints[i])
		if err != nil {
			panic(err)
		}
		grpcConn = conn
		grpcs <- conn
	}

	keys := ParseAccounts(keyFile)
	if keys == nil {
		panic("Load of accounts failed")
	}
	accounts := make(chan *Account, len(keys))
	for i := 0; i < len(keys); i++ {
		acc := NewAccount(keys[i], "cosmos", 0, 0)
		if acc == nil {
			panic("Failed to create account. Invalid key?")
		}
		acc.QueryInfo(grpcConn)
		accounts <- acc
	}

	tmConn := NewTMConnect(hostnport, path)
	if tmConn == nil {
		return nil, errors.New("connection failed")
	}
	store := &kvStore{freeSlots: freeSlots, accounts: accounts, grpcs: grpcs, conn: tmConn, closing: make(chan bool, 1), noTxs: make(chan bool, 5)}
	err = tmConn.BlockSubscribe(store)
	if err != nil {
		return nil, err
	}
	return store, nil
}

type kvStore struct {
	freeSlots chan bool
	accounts  chan *Account
	grpcs     chan *grpc.ClientConn
	conn      *TMConn
	closing   chan bool
	noTxs     chan bool
}

func (db *kvStore) Handle(msg []byte) {
	resp := RPCResp{}
	json.Unmarshal(msg, &resp)
	//result>data>value>block>data>txs
	for i := 0; i < len(resp.Result.Data.Value.Block.Data.Txs); i++ {
		db.freeSlots <- true
	}
	select {
	case end := <-db.closing:
		db.closing <- end
		if len(resp.Result.Data.Value.Block.Data.Txs) == 0 {
			db.noTxs <- end
		}
	default:
		return
	}
}

func (db *kvStore) InitThread(ctx context.Context, _ int, _ int) context.Context {
	return ctx
}

func (db *kvStore) CleanupThread(ctx context.Context) {
}

func (db *kvStore) Read(ctx context.Context, table string, key string, fields []string) (map[string][]byte, error) {
	account := <-db.accounts
	msgs := make([]sdk.Msg, len(fields))
	for i := 0; i < len(fields); i++ {
		msg := types.NewMsgReadKey(account.GetAddress(), table+key+fields[i])
		msgs[i] = msg
	}
	bytes, err := BuildSign("test-chain-95APpL", account, msgs)
	if err != nil {
		panic(err)
	}
	<-db.freeSlots
	conn := <-db.grpcs
	err = SendBytesAsync(conn, bytes)
	if err != nil {
		panic(err)
	}
	account.IncreaseAccSeq()
	db.accounts <- account
	db.grpcs <- conn
	return nil, nil
}

func (db *kvStore) Scan(ctx context.Context, table string, startKey string, count int, fields []string) ([]map[string][]byte, error) {
	panic("Scan invoked")
}

func (db *kvStore) Update(ctx context.Context, table string, key string, values map[string][]byte) error {
	account := <-db.accounts
	msgs := make([]sdk.Msg, len(values))
	i := 0
	for k, v := range values {
		s := hex.EncodeToString(v)
		msg := types.NewMsgWriteKey(account.GetAddress(), table+key+k, s[0:len(s)/2])
		msgs[i] = msg
		i++
	}
	bytes, err := BuildSign("test-chain-95APpL", account, msgs)
	if err != nil {
		panic(err)
	}
	<-db.freeSlots
	conn := <-db.grpcs
	err = SendBytesAsync(conn, bytes)
	if err != nil {
		panic(err)
	}
	account.IncreaseAccSeq()
	db.accounts <- account
	db.grpcs <- conn
	return nil
}

func (db *kvStore) Insert(ctx context.Context, table string, key string, values map[string][]byte) error {
	account := <-db.accounts
	msgs := make([]sdk.Msg, len(values))
	i := 0
	for k, v := range values {
		s := hex.EncodeToString(v)
		msg := types.NewMsgWriteKey(account.GetAddress(), table+key+k, s[0:len(s)/2])
		msgs[i] = msg
		i++
	}
	bytes, err := BuildSign("test-chain-95APpL", account, msgs)
	if err != nil {
		panic(err)
	}
	<-db.freeSlots
	conn := <-db.grpcs
	err = SendBytesAsync(conn, bytes)
	if err != nil {
		panic(err)
	}
	account.IncreaseAccSeq()
	db.accounts <- account
	db.grpcs <- conn
	return nil
}

func (db *kvStore) Delete(ctx context.Context, table string, key string) error {
	account := <-db.accounts
	msg := types.NewMsgDeleteKey(account.GetAddress(), table+key)
	bytes, err := BuildSign("test-chain-95APpL", account, []sdk.Msg{msg})
	if err != nil {
		panic(err)
	}
	<-db.freeSlots
	conn := <-db.grpcs
	err = SendBytesAsync(conn, bytes)
	if err != nil {
		panic(err)
	}
	account.IncreaseAccSeq()
	db.accounts <- account
	db.grpcs <- conn
	return nil
}

func (db *kvStore) Close() error {
	db.closing <- true
	<-db.noTxs
	<-db.noTxs
	<-db.noTxs
	<-db.noTxs
	<-db.noTxs
	db.conn.Close()
	close(db.grpcs)
	for conn := range db.grpcs {
		conn.Close()
	}
	return nil
}

package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

func RegisterCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgWriteKey{}, "kvstore/WriteKey", nil)
	cdc.RegisterConcrete(&MsgDeleteKey{}, "kvstore/DeleteKey", nil)
	cdc.RegisterConcrete(&MsgReadKey{}, "kvstore/ReadKey", nil)
	// this line is used by starport scaffolding # 2
}

func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgWriteKey{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgDeleteKey{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgReadKey{},
	)
	// this line is used by starport scaffolding # 3

	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}

var (
	Amino     = codec.NewLegacyAmino()
	ModuleCdc = codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())
)

package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const TypeMsgWriteKey = "write_key"

var _ sdk.Msg = &MsgWriteKey{}

func NewMsgWriteKey(creator string, key string, value string) *MsgWriteKey {
	return &MsgWriteKey{
		Creator: creator,
		Key:     key,
		Value:   value,
	}
}

func (msg *MsgWriteKey) Route() string {
	return RouterKey
}

func (msg *MsgWriteKey) Type() string {
	return TypeMsgWriteKey
}

func (msg *MsgWriteKey) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

func (msg *MsgWriteKey) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

func (msg *MsgWriteKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

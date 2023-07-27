package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const TypeMsgReadKey = "read_key"

var _ sdk.Msg = &MsgReadKey{}

func NewMsgReadKey(creator string, key string) *MsgReadKey {
	return &MsgReadKey{
		Creator: creator,
		Key:     key,
	}
}

func (msg *MsgReadKey) Route() string {
	return RouterKey
}

func (msg *MsgReadKey) Type() string {
	return TypeMsgReadKey
}

func (msg *MsgReadKey) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

func (msg *MsgReadKey) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

func (msg *MsgReadKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

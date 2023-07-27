package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const TypeMsgDeleteKey = "delete_key"

var _ sdk.Msg = &MsgDeleteKey{}

func NewMsgDeleteKey(creator string, key string) *MsgDeleteKey {
	return &MsgDeleteKey{
		Creator: creator,
		Key:     key,
	}
}

func (msg *MsgDeleteKey) Route() string {
	return RouterKey
}

func (msg *MsgDeleteKey) Type() string {
	return TypeMsgDeleteKey
}

func (msg *MsgDeleteKey) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

func (msg *MsgDeleteKey) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

func (msg *MsgDeleteKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

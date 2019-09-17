package protocol

import (
	"errors"
	"strings"

	"github.com/zu1k/gossr/ssr"
)

type creator func() IProtocol

var (
	creatorMap              = make(map[string]creator)
	NotSupportProtocolError = errors.New("protocol do not support")
)

type IProtocol interface {
	SetServerInfo(s *ssr.ServerInfoForObfs)
	GetServerInfo() *ssr.ServerInfoForObfs
	PreEncrypt(data []byte) ([]byte, error)
	PostDecrypt(data []byte) ([]byte, int, error)
	SetData(data interface{})
	GetData() interface{}
}

type authData struct {
	clientID     []byte
	connectionID uint32
}

func register(name string, c creator) {
	creatorMap[name] = c
}

func NewProtocol(name string) (iprotocol IProtocol, err error) {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c(), nil
	}
	return nil, NotSupportProtocolError
}

package obfs

import (
	"errors"
	"strings"

	"github.com/zu1k/gossr/ssr"
)

type creator func() IObfs

var (
	creatorMap          = make(map[string]creator)
	NotSupportObfsError = errors.New("obfs method do not support")
)

type IObfs interface {
	SetServerInfo(s *ssr.ServerInfoForObfs)
	GetServerInfo() (s *ssr.ServerInfoForObfs)
	Encode(data []byte) ([]byte, error)
	Decode(data []byte) ([]byte, uint64, error)
	SetData(data interface{})
	GetData() interface{}
}

func register(name string, c creator) {
	creatorMap[name] = c
}

// NewObfs create an obfs object by name and return as an IObfs interface
func NewObfs(name string) (iobfs IObfs, err error) {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c(), nil
	}
	return nil, NotSupportObfsError
}

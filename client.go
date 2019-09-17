package shadowsocksr

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zu1k/gossr/obfs"
	"github.com/zu1k/gossr/protocol"
	"github.com/zu1k/gossr/ssr"
)

func NewSSRClient(u *url.URL) (*SSTCPConn, error) {
	query := u.Query()
	encryptMethod := query.Get("encrypt-method")
	encryptKey := query.Get("encrypt-key")
	cipher, err := NewStreamCipher(encryptMethod, encryptKey)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{
		Timeout: time.Millisecond * 500,
	}
	conn, err := dialer.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}

	ssconn := NewSSTCPConn(conn, cipher)
	if ssconn.Conn == nil || ssconn.RemoteAddr() == nil {
		return nil, errors.New("nil connection")
	}

	// should initialize obfs/protocol now
	rs := strings.Split(ssconn.RemoteAddr().String(), ":")
	port, _ := strconv.Atoi(rs[1])

	ssconn.IObfs, err = obfs.NewObfs(query.Get("obfs"))
	if err != nil {
		return nil, err
	}
	obfsServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  query.Get("obfs-param"),
	}
	ssconn.IObfs.SetServerInfo(obfsServerInfo)
	ssconn.IProtocol, err = protocol.NewProtocol(query.Get("protocol"))
	if err != nil {
		return nil, err
	}
	protocolServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  query.Get("protocol-param"),
	}
	ssconn.IProtocol.SetServerInfo(protocolServerInfo)

	return ssconn, nil
}

package protocol

import "github.com/zu1k/gossr/tools"

//func init() {
//	register("auth_aes128_sha1", NewAuthAES128SHA1)
//}
//
//func NewAuthAES128SHA1() IProtocol {
//	a := &authAES128{
//		salt:       "auth_aes128_sha1",
//		hmac:       tools.HmacSHA1,
//		hashDigest: tools.SHA1Sum,
//		packID:     1,
//		recvInfo: recvInfo{
//			recvID: 1,
//			buffer: bytes.NewBuffer(nil),
//		},
//		data: &authData{
//			connectionID: 0xFF000001,
//		},
//	}
//	return a
//}


func init() {
	register("auth_aes128_sha1", newAuthAES128SHA1)
}

func newAuthAES128SHA1() IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_sha1",
		hmac:       tools.HmacSHA1,
		hashDigest: tools.SHA1Sum,
		packID:     1,
		recvInfo: recvInfo{
			recvID: 1,
		},
	}
	return a
}
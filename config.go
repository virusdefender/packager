package packager

import (
	"crypto/rsa"
	"crypto/x509"
)

type PackConfig struct {
	// 用于区分不同的包类型和加密配置等，可以从文件前32个字节中读取
	Magic       [MagicSize]byte
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate

	// 存放任意的额外想带上的数据
	ExtraData map[string]string

	// EncryptExtraData 是否加密 ExtraData
	// 有时候不想让其他人轻而易举的看到文件的 ExtraData，所以可以设置为加密状态
	// 但是有时候通过浏览器上传文件的时候，还希望在网页上上传前做一个初步的校验和信息的展示，这个时候就需要在前端代码中设置 ExtraDataAesKey
	// 这样用户就可能获取到 ExtraDataAesKey，所以 ExtraDataAesKey 和 MainDataAesKey 不要设置为一样的，避免在上述的场景下同时泄露。
	EncryptExtraData bool
	ExtraDataAesKey  [Aes256KeySize]byte

	// MainDataAesKey 用于加密文件的主体数据，因为是对称加密，所以实际上也存在泄露的可能
	// 本程序假设这个 key 可能存在泄露，但是保证泄露之后攻击者也无法重打包，因为还有一个非对称的签名验证过程
	MainDataAesKey [Aes256KeySize]byte
}

type UnpackConfig struct {
	CACertificate   *x509.Certificate
	ExtraDataAesKey [Aes256KeySize]byte
	MainDataAesKey  [Aes256KeySize]byte
	// 是否校验证书的有效期，一般情况下不需要
	VerifyCertificateTime bool
}

// 写入文件的头部信息
type fileHeader struct {
	Magic                [MagicSize]byte
	IV                   [16]byte
	ExtraDataIsEncrypted bool
	ExtraDataLength      uint64
	CertificateLength    uint64
	MainDataLength       uint64
	SignatureLength      uint16
}

const (
	Aes256KeySize = 32
	MagicSize     = 32
)

package packager

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"github.com/virusdefender/goutils/errors"
	"io"
	"time"
)

type UnpackConfigHandler interface {
	// 根据 Magic 选择对应的配置
	GetConfig(magic [MagicSize]byte) (*UnpackConfig, error)
}

type UnpackHandler interface {
	UnpackConfigHandler
	// ExtraData 是在文件中直接获取的，此未经签名验证，需要使用函数的返回值中提供的数据进行二次校验
	// 如果返回 false 则不再进行后续处理，比如证书不在允许范围内等原因
	HandleUnverifiedExtraDataAndCert(extraData map[string]string, cert *x509.Certificate) bool
}

func Unpack(input io.Reader, output io.Writer, handler UnpackHandler) (map[string]string, *x509.Certificate, error) {
	// 读取文件头部信息
	header := fileHeader{}
	err := binary.Read(input, binary.LittleEndian, &header)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read header")
	}

	config, err := handler.GetConfig(header.Magic)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get config")
	}

	// 读取 ExtraData
	extraDataBytes := make([]byte, header.ExtraDataLength)
	err = binary.Read(input, binary.LittleEndian, extraDataBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read extra data")
	}

	hasher := sha256.New()
	_, err = hasher.Write(extraDataBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write metadata")
	}

	// 如果 ExtraData 是加密的就去解密
	if header.ExtraDataIsEncrypted {
		block, err := aes.NewCipher(config.ExtraDataAesKey[:])
		if err != nil {
			return nil, nil, errors.Wrap(err, "new cipher")
		}
		ctr := cipher.NewCTR(block, header.IV[:])
		ctr.XORKeyStream(extraDataBytes, extraDataBytes)
	}

	// 反序列化 ExtraData
	extraData := make(map[string]string)
	err = json.Unmarshal(extraDataBytes, &extraData)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal extra data failed, maybe wrong aes key")
	}

	// 获取证书
	certBytes := make([]byte, header.CertificateLength)
	_, err = io.ReadFull(input, certBytes)
	if err != nil {
		return extraData, nil, errors.Wrap(err, "read certificate")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return extraData, nil, errors.Wrap(err, "parse certificate")
	}

	// 验证证书是否是指定的 ca 颁发
	caPool := x509.NewCertPool()
	caPool.AddCert(config.CACertificate)
	opts := x509.VerifyOptions{Roots: caPool}
	if !config.VerifyCertificateTime {
		opts.CurrentTime = cert.NotAfter.Add(time.Second * -1)
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return extraData, cert, errors.Wrap(err, "verify certificate")
	}

	// 如果返回了 false 就代表不再继续处理了，比如证书不在允许范围内等原因
	if !handler.HandleUnverifiedExtraDataAndCert(extraData, cert) {
		return nil, nil, nil
	}

	decryptMainBody := output != io.Discard
	var ctr cipher.Stream
	if decryptMainBody {
		block, err := aes.NewCipher(config.MainDataAesKey[:])
		if err != nil {
			return extraData, cert, errors.Wrap(err, "new cipher")
		}
		ctr = cipher.NewCTR(block, header.IV[:])
	}

	chunkSize := uint64(1024 * 1024 * 4)
	sizeLeft := header.MainDataLength
	buf := make([]byte, chunkSize)

	// 读取并解密主数据
	for {
		if sizeLeft <= 0 {
			break
		}
		curChunkSize := chunkSize
		if sizeLeft < chunkSize {
			curChunkSize = sizeLeft
		}
		_, err = io.ReadFull(input, buf[:curChunkSize])
		if err != nil {
			return extraData, cert, errors.Wrap(err, "read input")
		}
		sizeLeft -= curChunkSize
		_, err = hasher.Write(buf[:curChunkSize])
		if err != nil {
			return extraData, cert, errors.Wrap(err, "write hasher")
		}
		if decryptMainBody {
			ctr.XORKeyStream(buf[:curChunkSize], buf[:curChunkSize])
			_, err = output.Write(buf[:curChunkSize])
			if err != nil {
				return extraData, cert, errors.Wrap(err, "write output")
			}
		}
	}

	// 读取签名
	signature := make([]byte, header.SignatureLength)
	_, err = io.ReadFull(input, signature)
	if err != nil {
		return extraData, cert, errors.Wrap(err, "read signature")
	}

	// 验证签名
	h := hasher.Sum(nil)
	err = rsa.VerifyPSS(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, h, signature, nil)
	if err != nil {
		return extraData, cert, errors.Wrap(err, "verify signature")
	}

	return extraData, cert, nil
}

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

func GetExtraData(config *UnpackConfig, input io.Reader, verify bool) (map[string]string, *x509.Certificate, error) {
	return unpack(config, input, io.Discard, verify, true)
}

func Unpack(config *UnpackConfig, input io.Reader, output io.Writer) (map[string]string, *x509.Certificate, error) {
	return unpack(config, input, output, true, false)
}

func unpack(config *UnpackConfig, input io.Reader, output io.Writer, verifyExtraData bool, metaDataOnly bool) (map[string]string, *x509.Certificate, error) {
	// 读取文件头部信息
	header := fileHeader{}
	err := binary.Read(input, binary.LittleEndian, &header)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read header")
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
	metaData := make(map[string]string)
	err = json.Unmarshal(extraDataBytes, &metaData)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal extra data failed, maybe wrong aes key")
	}

	if !verifyExtraData {
		return metaData, nil, nil
	}

	// 获取证书
	certBytes := make([]byte, header.CertificateLength)
	_, err = io.ReadFull(input, certBytes)
	if err != nil {
		return metaData, nil, errors.Wrap(err, "read certificate")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return metaData, nil, errors.Wrap(err, "parse certificate")
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
		return metaData, cert, errors.Wrap(err, "verify certificate")
	}

	var ctr cipher.Stream
	if !metaDataOnly {
		block, err := aes.NewCipher(config.MainDataAesKey[:])
		if err != nil {
			return metaData, cert, errors.Wrap(err, "new cipher")
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
			return metaData, cert, errors.Wrap(err, "read input")
		}
		sizeLeft -= curChunkSize
		_, err = hasher.Write(buf[:curChunkSize])
		if err != nil {
			return metaData, cert, errors.Wrap(err, "write hasher")
		}
		if !metaDataOnly {
			ctr.XORKeyStream(buf[:curChunkSize], buf[:curChunkSize])
			_, err = output.Write(buf[:curChunkSize])
			if err != nil {
				return metaData, cert, errors.Wrap(err, "write output")
			}
		}
	}

	// 读取签名
	signature := make([]byte, header.SignatureLength)
	_, err = io.ReadFull(input, signature)
	if err != nil {
		return metaData, cert, errors.Wrap(err, "read signature")
	}

	// 验证签名
	h := hasher.Sum(nil)
	err = rsa.VerifyPSS(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, h, signature, nil)
	if err != nil {
		return metaData, cert, errors.Wrap(err, "verify signature")
	}

	return metaData, cert, nil
}

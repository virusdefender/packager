package packager

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"github.com/virusdefender/goutils/errors"
	"io"
)

func Pack(config *PackConfig, input io.Reader, inputSize uint64, output io.Writer) error {
	extraDataBytes, err := json.Marshal(config.ExtraData)
	if err != nil {
		return errors.Wrap(err, "marshal extra data")
	}

	header := fileHeader{
		Magic:                config.Magic,
		ExtraDataIsEncrypted: config.EncryptExtraData,
		ExtraDataLength:      uint64(len(extraDataBytes)),
		CertificateLength:    uint64(len(config.Certificate.Raw)),
		MainDataLength:       inputSize,
		SignatureLength:      uint16(config.PrivateKey.Size()),
	}

	_, err = io.ReadFull(rand.Reader, header.IV[:])
	if err != nil {
		return errors.Wrap(err, "read random")
	}

	if config.EncryptExtraData {
		block, err := aes.NewCipher(config.ExtraDataAesKey[:])
		if err != nil {
			return errors.Wrap(err, "new cipher")
		}
		ctr := cipher.NewCTR(block, header.IV[:])
		ctr.XORKeyStream(extraDataBytes, extraDataBytes)
	}

	// 写入文件头部信息
	err = binary.Write(output, binary.LittleEndian, header)
	if err != nil {
		return errors.Wrap(err, "write header")
	}

	hasher := sha256.New()

	// 写入 MetaData
	_, err = io.MultiWriter(hasher, output).Write(extraDataBytes)
	if err != nil {
		return errors.Wrap(err, "write metadata")
	}

	// 写入证书
	_, err = output.Write(config.Certificate.Raw)
	if err != nil {
		return errors.Wrap(err, "write certificate")
	}

	block, err := aes.NewCipher(config.MainDataAesKey[:])
	ctr := cipher.NewCTR(block, header.IV[:])

	sizeLeft := inputSize
	chunkSize := uint64(1024 * 1024 * 4)
	plainBuf := make([]byte, chunkSize)
	encryptedBuf := make([]byte, chunkSize)

	// 加密并循环写入 MainData
	for {
		if sizeLeft <= 0 {
			break
		}
		curChunkSize := chunkSize
		if sizeLeft < chunkSize {
			curChunkSize = sizeLeft
		}
		_, err = io.ReadFull(input, plainBuf[:curChunkSize])
		if err != nil {
			return errors.Wrap(err, "read input")
		}
		sizeLeft -= curChunkSize

		ctr.XORKeyStream(encryptedBuf[:curChunkSize], plainBuf[:curChunkSize])

		_, err = io.MultiWriter(hasher, output).Write(encryptedBuf[:curChunkSize])
		if err != nil {
			return errors.Wrap(err, "write output")
		}
	}

	// 生成并写入签名
	h := hasher.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, config.PrivateKey, crypto.SHA256, h, nil)
	if err != nil {
		return errors.Wrap(err, "sign")
	}

	_, err = output.Write(signature)
	if err != nil {
		return errors.Wrap(err, "write signature")
	}

	return nil
}

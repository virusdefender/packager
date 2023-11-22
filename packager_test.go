package packager

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"github.com/virusdefender/goutils/assert"
	"strings"
	"testing"
)

func mustGenKey() [32]byte {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	return key
}

type testUnpackHandler struct {
	config *UnpackConfig
}

func (t *testUnpackHandler) GetConfig(magic [32]byte) (*UnpackConfig, error) {
	return t.config, nil
}

func (t *testUnpackHandler) HandleUnverifiedExtraDataAndCert(data map[string]string, cert *x509.Certificate) bool {
	return true
}

func TestPackager(t *testing.T) {
	rootPrivateKey, rootCertificate, err := GenerateRoot("Packager Test Root CA")
	assert.Nil(t, err)

	_, rootCertificateUntrust, err := GenerateRoot("Packager Test Root CA - Untrust")
	assert.Nil(t, err)

	endPrivateKey, endCertificate, err := GenerateEnd("test", rootPrivateKey, rootCertificate)
	assert.Nil(t, err)

	rawData := []byte(strings.Repeat("A", 1000))
	packed := &bytes.Buffer{}

	magic := [MagicSize]byte{'t', 'e', 's', 't', 'p', 'k', 'g', '_', 'v', '1'}
	extraDataAesKey := mustGenKey()
	mainDataAesKey := mustGenKey()

	packConfig := &PackConfig{
		Magic:            magic,
		PrivateKey:       endPrivateKey,
		Certificate:      endCertificate,
		ExtraData:        map[string]string{"key": "value"},
		EncryptExtraData: true,
		ExtraDataAesKey:  extraDataAesKey,
		MainDataAesKey:   mainDataAesKey,
	}

	// 正常打包
	err = Pack(packConfig, bytes.NewReader(rawData), uint64(len(rawData)), packed)
	assert.Nil(t, err)
	packedData := packed.Bytes()

	unpackConfig := &UnpackConfig{
		CACertificate:   rootCertificate,
		ExtraDataAesKey: extraDataAesKey,
		MainDataAesKey:  mainDataAesKey,
	}
	unpackConfigUnstrustCa := &UnpackConfig{
		CACertificate:   rootCertificateUntrust,
		ExtraDataAesKey: extraDataAesKey,
		MainDataAesKey:  mainDataAesKey,
	}
	unpacked := &bytes.Buffer{}

	// 正常解包
	handler := &testUnpackHandler{config: unpackConfig}
	extraData, cert, err := Unpack(bytes.NewReader(packedData), unpacked, handler)
	assert.Nil(t, err)
	assert.Equal(t, extraData, map[string]string{"key": "value"})
	assert.Equal(t, cert.Subject.CommonName, "test")
	assert.Equal(t, unpacked.Bytes(), rawData)

	// 不信任的证书
	handler = &testUnpackHandler{config: unpackConfigUnstrustCa}
	handler.config.CACertificate = rootCertificateUntrust
	_, _, err = Unpack(bytes.NewBuffer(packedData), unpacked, handler)
	assert.True(t, err != nil)
	assert.True(t, strings.Contains(err.Error(), "signed by unknown authority"))

	// 获取 ExtraData，校验签名
	handler = &testUnpackHandler{config: unpackConfig}
	packed = bytes.NewBuffer(packed.Bytes())
	extraData, cert, err = GetMetaData(bytes.NewBuffer(packedData), handler, true)
	assert.Nil(t, err)
	assert.Equal(t, extraData, map[string]string{"key": "value"})
	assert.Equal(t, cert.Subject.CommonName, "test")

	// 获取 ExtraData，但是给一个修改过的包，校验签名的情况下应该抛出错误
	malformedPackedData := make([]byte, len(packedData))
	copy(malformedPackedData, packedData)
	malformedPackedData[len(malformedPackedData)-1] = malformedPackedData[len(malformedPackedData)-1] + 1

	_, _, err = GetMetaData(bytes.NewBuffer(malformedPackedData), handler, true)
	assert.True(t, err != nil)
	assert.True(t, strings.Contains(err.Error(), "verification error"))

	// 获取 ExtraData，但是给一个修改过的包，不校验签名的情况下应该正常返回
	extraData, _, err = GetMetaData(bytes.NewBuffer(malformedPackedData), handler, false)
	assert.Nil(t, err)
	assert.Equal(t, extraData, map[string]string{"key": "value"})
}

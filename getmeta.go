package packager

import (
	"crypto/x509"
	"io"
)

type getMetaHandler struct {
	UnpackConfigHandler
	verify    bool
	extraData map[string]string
	cert      *x509.Certificate
}

func (g *getMetaHandler) HandleUnverifiedExtraDataAndCert(extraData map[string]string, cert *x509.Certificate) bool {
	g.extraData = extraData
	g.cert = cert
	return g.verify
}

func GetMetaData(input io.Reader, handler UnpackConfigHandler, verify bool) (map[string]string, *x509.Certificate, error) {
	if verify {
		return Unpack(input, io.Discard, &getMetaHandler{UnpackConfigHandler: handler, verify: true})
	} else {
		h := &getMetaHandler{UnpackConfigHandler: handler, verify: false}
		_, _, err := Unpack(input, io.Discard, h)
		if err != nil {
			return nil, nil, err
		}
		return h.extraData, h.cert, nil
	}
}

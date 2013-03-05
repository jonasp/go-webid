package webid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/dsa"
	"encoding/asn1"
	"math/big"
	"time"
	"errors"
)

type webidCert struct {
	subjectAltName string
	publicKey      interface{}	
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

func parseX509Cert(in *x509.Certificate) (*webidCert, error) {
	var cert certificate
	if _, err := asn1.Unmarshal(in.Raw, &cert); err != nil {
		return nil, err
	}

	out := new(webidCert)

	var err error
	out.subjectAltName, err = parseSubjectAltName(&cert)
	if err != nil {
		return nil, err
	}

	out.publicKey, err = parsePublicKey(&cert)
	if err != nil {
		return nil, err
	}

	return out, nil
}

type rsaPublicKey struct {
	N *big.Int
	E int
}

type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
)

var (
	oidPublicKeyRsa = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDsa = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRsa):
		return RSA
	case oid.Equal(oidPublicKeyDsa):
		return DSA
	}
	return UnknownPublicKeyAlgorithm
}

func parsePublicKey(cert *certificate) (interface{}, error) {
	pki := cert.TBSCertificate.PublicKey
	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == UnknownPublicKeyAlgorithm {
		return nil,  errors.New("unknown publc key algorithm")
	}
	keyData := &pki
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case RSA:
		p := new(rsaPublicKey)
		_, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case DSA:
		var p *big.Int
		_, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, err
		}
		paramsData := keyData.Algorithm.Parameters.FullBytes
		params := new(dsaAlgorithmParameters)
		_, err = asn1.Unmarshal(paramsData, params)
		if err != nil {
			return nil, err
		}
		if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
			return nil, errors.New("zero or negative DSA parameter")
		}
		pub := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
			Y: p,
		}
		return pub, nil
	default:
		return nil, nil
	}
	panic("unreachable")
}

func parseSubjectAltName(cert *certificate) (string, error) {
	for _, ext := range cert.TBSCertificate.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			var seq asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &seq)
			if err != nil {
				return "", err
			}
			if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
				return "", asn1.StructuralError{Msg: "bad SAN sequence"}
			}

			var v asn1.RawValue
			_, err = asn1.Unmarshal(seq.Bytes, &v)
			if err != nil {
				return "", err
			}
			if v.Tag == 6 {
				return string(v.Bytes), nil
			}
		}
	}

	return "", nil
}

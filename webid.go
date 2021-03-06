package webid

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"math/big"
	"strconv"
	"bitbucket.org/ww/goraptor"
)

type tripple struct {
	subject, predicate, object string
}

type id struct {
	Name  string
	Valid bool
}

func Validate(tls *tls.ConnectionState) (*id, error) {
	if len(tls.PeerCertificates) == 0 {
		return nil, errors.New("no certificate")
	}

	in := tls.PeerCertificates[0]
	cert, err := parseX509Cert(in)
	if err != nil {
		return nil, err
	}

	out := id{cert.subjectAltName, false}

	switch pub := cert.publicKey.(type) {
	case *rsa.PublicKey:
		tripples, err := parseURI(cert.subjectAltName)
		if err != nil {
			return nil, err
		}

		var keyId string
		for _, t := range tripples {
			if t.subject == cert.subjectAltName &&
				t.predicate == "http://www.w3.org/ns/auth/cert#key" {
				keyId = t.object
			}
		}

		mod := big.NewInt(0)
		var exp int
		for _, t := range tripples {
			if t.subject == keyId {
				if t.predicate == "http://www.w3.org/ns/auth/cert#modulus" {
					_, ok := mod.SetString(t.object, 16)
					if !ok {
						return nil, errors.New("invalid modulus in WebID")
					}
				}
				if t.predicate == "http://www.w3.org/ns/auth/cert#exponent" {
					exp64, err := strconv.ParseInt(t.object, 10, 0)
					if err != nil {
						return nil, err
					}
					exp = int(exp64)
				}
			}
		}
		out.Valid = mod.Cmp(pub.N) == 0 && exp == pub.E
	default:
		return nil, errors.New("unknown PublicKey format")
	}

	return &out, nil
}

func parseURI(s string) ([]tripple, error) {
	parser := goraptor.NewParser("guess")
	defer parser.Free()

	var tripples []tripple
	ch := parser.ParseUri(s, "")
	for v := range ch {
		tripples = append(tripples, tripple{
			v.Subject.String(),
			v.Predicate.String(),
			v.Object.String(),
		})
	}

	return tripples, nil
}

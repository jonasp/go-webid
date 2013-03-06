package webid

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"turtle/parse"
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
			if t.subject == cert.URIs[0] &&
				t.predicate == "<http://www.w3.org/ns/auth/cert#key>" {
				keyId = t.object
			}
		}

		mod := big.NewInt(0)
		var exp int
		for _, t := range tripples {
			if t.subject == keyId {
				if t.predicate == "<http://www.w3.org/ns/auth/cert#modulus>" {
					modString := strings.Split(t.object, "^^")[0]
					_, ok := mod.SetString(modString[1:len(modString)-1], 16)
					if !ok {
						return nil, errors.New("invalid modulus in WebID")
					}
				}
				if t.predicate == "<http://www.w3.org/ns/auth/cert#exponent>" {
					expString := strings.Split(t.object, "^^")[0]
					exp64, err := strconv.ParseInt(expString[1:len(expString)-1], 10, 0)
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
	resp, err := http.Get(s)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var tripples []tripple
	ch := parse.Parse("test", string(body))
	for v := range ch {
		if v.Ok == false {
			return nil, errors.New("could not parse webid")
		}
		tripples = append(tripples, tripple{v.Subject, v.Predicate, v.Object})
	}
	return tripples, nil
}

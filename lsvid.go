package lsvid

// Package developed by SPIFFE Assertions and Tokens WG, to provide, extend and validate Lightweight SVID.
// Ref document:
// https://docs.google.com/document/d/15rfAkzNTQa1ycs-fn9hyIYV5HbznPBsxB-f0vxhNJ24

// Notes:
// This is a proof of concept that requires the SPIRE-devon fork (hpe-spiffe-spire project) to run. 
// This spire fork modifies the FetchJWTSVID endpoint to return the workload LSVID.
// It also requires the go-spiffe modified pkg that skip the JWT-SVID validation.

// ToDo: 
// Temporary: Make spire-devon public and publish also the modified go-spiffe package.

import (

	"context"
	"fmt"
	"encoding/base64"
	"encoding/json"
	"crypto"
	"crypto/rand"
	hash256 "crypto/sha256"
	"crypto/x509"
	"crypto/ecdsa"
	"log"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"time"

	"github.com/hpe-usp-spire/schoco"

)

type LSVID struct {
	Token		*Token		`json:"token"`		// The workload LSVID document
	Bundle		*Token		`json:"bundle"`		// The Trust bundle document
}

// The token must contain a Payload and a Signature. The Nested value is optional, and must be used when extending the token.
type Token struct {	
	Nested		*Token		`json:"nested,omitempty"`
	Payload		*Payload	`json:"payload"`
	Signature	[]byte		`json:"signature"`
}

// The mandatory claims are pre-defined. Any other info to be added must be inserted in Data.
// For proof of concept compatibility purposes, we are keeping the Dpr and Dpa claims. It must be removed later.
type Payload struct {
	Ver 		int8					`json:"ver,omitempty"`
	Alg 		string					`json:"alg,omitempty"`
	Iat			int64					`json:"iat,omitempty"`
	Iss			*IDClaim				`json:"iss,omitempty"`
	Sub			*IDClaim				`json:"sub,omitempty"`
	Aud			*IDClaim				`json:"aud,omitempty"`
	Dpa			string					`json:"dpa,omitempty"`
	Dpr			string					`json:"dpr,omitempty"`
	Data		map[string]interface{}	`json:"data,omitempty"`
}

type IDClaim struct {
	CN			string		`json:"cn,omitempty"` // e.g.: spiffe://example.org/workload
	PK			[]byte		`json:"pk,omitempty"` // e.g.: VGhpcyBpcyBteSBQdWJsaWMgS2V5
	ID			*Token		`json:"id,omitempty"` // e.g.: a complete LSVID
}

// lsvid -> string
func Encode(lsvid *LSVID) (string, error) {
	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(lsvid)
	if err != nil {
		return "", fmt.Errorf("error marshaling LSVID to JSON: %v\n", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

	return encLSVID, nil
}

// string -> lsvid
func Decode(encLSVID string) (*LSVID, error) {

    // Decode the base64.RawURLEncoded LSVID
    decoded, err := base64.RawURLEncoding.DecodeString(encLSVID)
    if err != nil {
        return nil, fmt.Errorf("error decoding LSVID: %v\n", err)
    }
	fmt.Printf("Decoded LSVID to be unmarshaled: %s\n", decoded)

    // Unmarshal the decoded byte slice into your struct
    var decLSVID LSVID
    err = json.Unmarshal(decoded, &decLSVID)
    if err != nil {
        return nil, fmt.Errorf("error unmarshalling LSVID: %v\n", err)
    }
	fmt.Printf("Return vallue: %v\n", decLSVID)
    return &decLSVID, nil
}

// Add the new Token to extend an existing one, and sign using provided key
func Extend(token *LSVID, newPayload *Payload, version int8, key ...interface{}) (string, error) {

	// Choose between ID / SchoCo
	var s []byte
	var newToken *Token
	// var outToken string
    switch version {
	case 0:

		// Create the extended LSVID structure
		token := &Token{
			Nested:		lsvid.Token,
			Payload:	newPayload,	
		}

		// Marshal to JSON
		tmpToSign, err := json.Marshal(token)
		if err != nil {
			return "", fmt.Errorf("Error generating json: %v\n", err)
		} 

		ecdsaKey, ok := key[0].(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}

		// Sign extlSVID
		hash 	:= hash256.Sum256(tmpToSign)
		s, err := ecdsaKey.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("Error generating signed assertion: %v\n", err)
		} 

		// Set extLSVID signature
		token.Signature = s

		// Create the extended LSVID
		extLSVID := &LSVID {
			Token:		token,
			Bundle:		lsvid.Bundle,
		}

		// Encode signed LSVID
		outLSVID, err := Encode(extLSVID)
		if err != nil {
			return "", fmt.Errorf("Error encoding LSVID: %v\n", err)
		} 
		
	case 1:
		// Uses schoco

		// Convert []byte to sig
		sig, err := schoco.ByteToSignature(token.Signature)

		// extract key from signature
		aggKey, partSig := sig.ExtractAggKey()

		// convert partsig to byte
		partSigBytes, err := schoco.PointToByte(partSig)
		if err != nil {
			return nil, fmt.Errorf("Error conveting point to byte: %v", err)
		} 
		token.Signature = partSigBytes

		// Define the new struct
		newToken = &Token{
			Nested:		token,
			Payload:	newPayload,	
		}

		// Marshal to JSON
		tmpToSign, err := json.Marshal(newToken)
		if err != nil {
			return nil, fmt.Errorf("Error generating json: %v\n", err)
		} 

		// Sign with aggKey key
		newSig := schoco.StdSign(fmt.Sprintf("%s", tmpToSign), aggKey)
		s, err = newSig.ToByte()
		if err != nil {
			return nil, fmt.Errorf("Error generating signed assertion: %v\n", err)
		} 
		// Set extToken signature
		newToken.Signature = s

		// Encode signed Token
		outLSVID, err = Encode(newToken)
		if err != nil {
			return "", fmt.Errorf("Error encoding LSVID: %v\n", err)
		}

	return outLSVID, nil
	}
}

// // Extend the existin lsvid with the new payload, signing with the aggregation key from last signature
// func AnonExtend(lsvid *LSVID, newPayload *Payload) (string, error) {
// 	// TODO: Modify the payload struct to support custom claims (maybe using map[string]{interface})

// 	// Create the extended LSVID structure
// 	token := &Token{
// 		Nested:		lsvid.Token,
// 		Payload:	newPayload,	
// 	}

// 	// Marshal to JSON
// 	tmpToSign, err := json.Marshal(token)
// 	if err != nil {
// 		return "", fmt.Errorf("Error generating json: %v\n", err)
// 	} 

// 	// unmarshal signature
// 	var sigFromBytes Signature
// 	err := json.Unmarshal(lsvid.Signature, &sigFromBytes)
// 	if err != nil {
// 		return "", fmt.Errorf("Error unmarshaling signature: %v\n", err)
// 	} 

// 	// // Extract aggregation key and partial signature
// 	// aggKey, partSig := sigFromBytes.ExtractAggKey()

// 	// // set partsig as new token signature
// 	// lsvid.Signature = []byte(partSig.String())

// 	// Aggregate
// 	// hash 	:= hash256.Sum256(tmpToSign)
// 	// s, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
// 	// if err != nil {
// 	// 	return "", fmt.Errorf("Error generating signed assertion: %v\n", err)
// 	// } 
// 	partSig, lastsig := schoco.Aggregate(tmpToSign, sigFromBytes)

// 	// set partsig as new token signature
// 	lsvid.Signature = []byte(partSig.String())

// 	// Set extLSVID signature
// 	token.Signature = []byte(lastsig.String())

// 	// Create the extended LSVID
// 	extLSVID := &LSVID {
// 		Token:		token,
// 		Bundle:		lsvid.Bundle,
// 	}

// 	// Encode signed LSVID
// 	outLSVID, err := Encode(extLSVID)
// 	if err != nil {
// 		return "", fmt.Errorf("Error encoding LSVID: %v\n", err)
// 	} 

// 	return outLSVID, nil

// }

// Validate the given LSVID. 
func Validate(lsvid *Token, version int8, bundle *Token) (bool, error) {
    
	switch version {
	case 0:
		// Validate ID Mode with ECDSA
		for (lsvid.Nested != nil) {

			// Check Aud -> Iss link
			if lsvid.Payload.Iss.CN != lsvid.Nested.Payload.Aud.CN {
				return false, fmt.Errorf("Aud -> Iss link validation failed\n")
			}
			fmt.Printf("Aud -> Iss link validation successful!\n")

			// Marshal the LSVID struct into JSON
			tmpLSVID := &Token{
				Nested:		lsvid.Nested,
				Payload:	lsvid.Payload,
			}
			lsvidJSON, err := json.Marshal(tmpLSVID)
			if err != nil {
			return false, fmt.Errorf("error marshaling LSVID to JSON: %v\n", err)
			}
			hash 	:= hash256.Sum256(lsvidJSON)

			// Parse the public key
			// TODO: Currently the pk is extracted from the iss lsvid that MUST be present
			// and we are still not validating the trust bundle.
			var issLSVID *LSVID
			issLSVID = lsvid.Payload.Iss.ID
			for (issLSVID.Nested != nil) {
				// fmt.Printf("Issuer nested LSVID found! %v\n", issLSVID.Nested)
				issLSVID = issLSVID.Nested
			}
			issLSSubPk, err := x509.ParsePKIXPublicKey(issLSVID.Payload.Sub.PK)
			if err != nil {
				return false, fmt.Errorf("Failed to parse public key: %v\n", err)
			}

			// validate the signature
			log.Printf("Verifying signature created by %s\n", lsvid.Payload.Iss.CN)
			verify := ecdsa.VerifyASN1(issLSSubPk.(*ecdsa.PublicKey), hash[:], lsvid.Signature)
			if verify == false {
				fmt.Printf("\nSignature validation failed!\n\n")
				return false, nil
			}
			log.Printf("Signature validation successful!\n")

			// jump to nested token
			lsvid = lsvid.Nested
		}

		// reached the inner most LSVID. 
		// Marshal the bundle struct into JSON
		bundleJSON, err := json.Marshal(bundle.Payload)
		if err != nil {
		return false, fmt.Errorf("error marshaling bundle LSVID to JSON: %v\n", err)
		}
		hash 	:= hash256.Sum256(bundleJSON)

		// Parse the public key
		issPk, err := x509.ParsePKIXPublicKey(bundle.Payload.Iss.PK)
		if err != nil {
			return false, fmt.Errorf("Failed to parse public key: %v\n", err)
		}
		log.Printf("Public key to be used: %s", issPk)

		log.Printf("Verifying signature created by %s\n", bundle.Payload.Iss.CN)
		verify := ecdsa.VerifyASN1(issPk.(*ecdsa.PublicKey), hash[:], bundle.Signature)
		if verify == false {
			fmt.Printf("\nBundle signature validation failed!\n\n")
			return false, nil
		}

	case 1:
		
		// Validate anon mode with SchoCo

		// Collect partial sigs and messages from all nested tokens
		var	setPartSig	[]kyber.Point
		var lastSig		schoco.Signature
		var	setMsg		[]string
		
		for i := 0; lsvid.Nested != nil; i++ {
			tmpToken := &LSVID{
				Nested:		lsvid.Nested,
				Payload:	lsvid.Payload,
			}

			// Marshal to JSON
			tokenJSON, err := json.Marshal(tmpToken)
			if err != nil {
				log.Printf("Error marshaling Token to JSON: %v\n", err)
			}
			// Collect signed message
			setMsg = append(setMsg, fmt.Sprintf("%s", tokenJSON))

			// Collect signature
			if i == 0 {
				lastSig, err = schoco.ByteToSignature(lsvid.Signature)
				if err != nil {
					log.Printf("Error converting byte to signature: %v\n", err)
				}
			} else {
				setPartSig[i], err = schoco.ByteToPoint(lsvid.Signature)
				if err != nil {
					log.Printf("Error converting byte to Point: %v\n", err)
				}
			}

			// jump to nested token
			token = lsvid.Nested

		}

		// reach most inner token
		// Collect msg
		tmpToken := &LSVID{
			Payload:	lsvid.Payload,
		}
		tokenJSON, err := json.Marshal(tmpToken)
		if err != nil {
			log.Printf("error marshaling Token to JSON: %v\n", err)
		}
		setMsg = append(setMsg, fmt.Sprintf("%s", tokenJSON))

		// collect partsig
		tmpPartSig, err := schoco.ByteToPoint(lsvid.Signature)
		if err != nil {
			log.Printf("Error converting byte to Point: %v\n", err)
		}
		setPartSig = append(setPartSig, tmpPartSig)

		// collect root pk
		rootPK, err := schoco.ByteToPoint(lsvid.Payload.Iss.PK)
		if err != nil {
			log.Printf("Error converting byte to Point: %v\n", err)
		}

		if !schoco.Verify(rootPK, setMsg, setPartSig, lastSig)	{
			log.Printf("Validate with schoco.Verify failed!\n")
		}
	}



	return true, nil
}

// Fetch workload LSVID using modified FetchJWTSVID endpoint
func FetchLSVID(ctx context.Context, socketPath string) (string, error) {
	
	// Fetch claims data
	clientSVID, err := FetchSVID(ctx, socketPath)
	if err != nil {
		return "", fmt.Errorf("Unable to fetch X509 SVID: %v\n", err)
	}
	clientID 		:= clientSVID.ID.String()

	source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return "", fmt.Errorf("Unable to create JWTSource %v\n", err)
	}
	defer source.Close()
	
	fetchLSVID, err := source.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: clientID,
	})
	if err != nil {
		return "", fmt.Errorf("Unable to Fetch LSVID %v\n", err)
	}

	return fmt.Sprintf("%s", fetchLSVID.LSVID.Svid), nil
}

// Helper funcs

// Create an LSVID payload given a x509 certificate.
// PS: Payload claims are based in LSVID spec doc
func Cert2LSR(ctx context.Context, socketPath string, cert *x509.Certificate, audience string) (*Payload, error) {

	clientSVID, err := FetchSVID(ctx, socketPath)
	if err != nil {
		return &Payload{}, fmt.Errorf("Unable to fetch X509 SVID: %v\n", err)
	}
	clientID 		:= clientSVID.ID.String()

	// generate encoded public key
	tmppk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return &Payload{}, err
	}
	// pubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

	// Versioning needs TBD. For poc, considering vr = 1
	if cert.URIs[0] == nil {
		return &Payload{}, fmt.Errorf("No certificate URI: %v", err)
	}
	sub := cert.URIs[0].String()
	// Create LSVID payload
	lsvidPayload := &Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&IDClaim{
			CN:	clientID,
		},
		Sub:	&IDClaim{
			CN:	sub,
			PK:	tmppk,
		},
		Aud:	&IDClaim{
			CN:	audience,
		},
	}

	return lsvidPayload, nil
}

// Fetch workload X509 SVID
// Used in fetchLSVID to retrieve the clientID.
// TODO: stop using this requires less imports. Keep it simple.
func FetchSVID(ctx context.Context, socketPath string) (*x509svid.SVID, error) {

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("Unable to create X509Source: %v\n", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch SVID: %v\n", err)
	}

	return svid, nil
}
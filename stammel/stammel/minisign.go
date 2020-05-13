package stammel

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
)

import "C"

type PublicKey struct {
	SignatureAlgorithm [2]byte
	KeyId              [8]byte
	PublicKey          [32]byte
}

type Signature struct {
	UntrustedComment   string
	SignatureAlgorithm [2]byte
	KeyId              [8]byte
	Signature          [64]byte
	TrustedComment     string
	GlobalSignature    [64]byte
}

func NewPublicKey(publicKeyStr string) (PublicKey, error) {
	var publicKey PublicKey
	bin, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil || len(bin) != 42 {
		return publicKey, errors.New("Invalid encoded public key")
	}
	copy(publicKey.SignatureAlgorithm[:], bin[0:2])
	copy(publicKey.KeyId[:], bin[2:10])
	copy(publicKey.PublicKey[:], bin[10:42])
	return publicKey, nil
}

func DecodePublicKey(in string) (PublicKey, error) {
	var publicKey PublicKey
	lines := strings.SplitN(in, "\n", 2)
	if len(lines) < 2 {
		return publicKey, errors.New("Incomplete encoded public key")
	}
	return NewPublicKey(lines[1])
}

func DecodeSignature(in string) (Signature, error) {
	var signature Signature
	lines := strings.SplitN(in, "\n", 4)
	if len(lines) < 4 {
		return signature, errors.New("Incomplete encoded signature")
	}
	signature.UntrustedComment = lines[0]
	bin1, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(bin1) != 74 {
		return signature, errors.New("Invalid encoded signature")
	}
	signature.TrustedComment = lines[2]
	bin2, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(bin2) != 64 {
		return signature, errors.New("Invalid encoded signature")
	}
	copy(signature.SignatureAlgorithm[:], bin1[0:2])
	copy(signature.KeyId[:], bin1[2:10])
	copy(signature.Signature[:], bin1[10:74])
	copy(signature.GlobalSignature[:], bin2)
	return signature, nil
}

//export EXP_CheckSignature
func EXP_CheckSignature(file string) (bool) {
	goto GO
Error:
	return false
GO:
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		goto Error
	}
	sig, err := ioutil.ReadFile(file + ".minisig")
	if err != nil {
		goto Error
	}
	pk, err := NewPublicKeyFromFile(file + ".pub")
	if err != nil {
		goto Error
	}
	signature, err := DecodeSignature(string(sig))
	if err == nil {
		if _, err = pk.Verify(bin, signature); err == nil {
		return true
		}
	}
	goto Error
}

//export EXP_CreateSign
func EXP_CreateSign(filename string) (bool) {
	goto GO
Error:
	return false
GO:
	cbin, err := ioutil.ReadFile(filename)
	if err != nil {
		goto Error
	}
	privName := filename + ".priv"
	pubName := filename + ".pub"
	timestamp := fmt.Sprintf("%d", time.Now().UTC().Unix())
	if _, err := os.Stat(privName); os.IsNotExist(err) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			goto Error
		}
		var tp = []byte(base64.StdEncoding.EncodeToString(priv))
		if err := ioutil.WriteFile(privName, tp, 0600); err != nil {
			goto Error
		}
		c := 8
		b := make([]byte, c)
		_, err = rand.Read(b)
		if err != nil {
			goto Error
		}
		comp := []string{"public key",
		base64.StdEncoding.EncodeToString(append(append([]byte{0x45,0x64}, b[:]...), pub[0:32]...))}
		var pb = []byte(strings.Join(comp, "\n"))
		if err := ioutil.WriteFile(pubName, pb, 0600); err != nil {
			goto Error
		}
	}
	pk, err := NewPublicKeyFromFile(pubName)
	if err != nil {
		goto Error
	}
	pvbin, err := ioutil.ReadFile(privName)
 	if err != nil {
		goto Error
	}
	pv, err := base64.StdEncoding.DecodeString(string(pvbin))
	if err != nil {
		goto Error
	}
	signature := ed25519.Sign(ed25519.PrivateKey(pv), cbin)
	trustedComment := "trusted comment: timestamp:" + timestamp + "	file:" + filepath.Base(filename)
	globalSignature := ed25519.Sign(ed25519.PrivateKey(pv), append(signature[:], []byte(trustedComment)[17:]...))
	compV := []string{
	"untrusted comment: signature from stammel ed25519 key",
	base64.StdEncoding.EncodeToString(append(append(pk.SignatureAlgorithm[:], pk.KeyId[:]...), signature[:]...)),
	trustedComment,
	base64.StdEncoding.EncodeToString(globalSignature)}
	var sbin = []byte(strings.Join(compV, "\n"))
	if err := ioutil.WriteFile(filename + ".minisig", sbin, 0600); err != nil {
		goto Error
	}
	return true
}

func NewPublicKeyFromFile(file string) (PublicKey, error) {
	var publicKey PublicKey
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return publicKey, err
	}
	return DecodePublicKey(string(bin))
}

func NewSignatureFromFile(file string) (Signature, error) {
	var signature Signature
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return signature, err
	}
	return DecodeSignature(string(bin))
}

func (publicKey *PublicKey) Verify(bin []byte, signature Signature) (bool, error) {
	if publicKey.SignatureAlgorithm != signature.SignatureAlgorithm {
		return false, errors.New("Incompatible signature algorithm")
	}
	if signature.SignatureAlgorithm[0] != 0x45 || signature.SignatureAlgorithm[1] != 0x64 {
		return false, errors.New("Unsupported signature algorithm")
	}
	if publicKey.KeyId != signature.KeyId {
		return false, errors.New("Incompatible key identifiers")
	}
	if !strings.HasPrefix(signature.TrustedComment, "trusted comment: ") {
		return false, errors.New("Unexpected format for the trusted comment")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey.PublicKey[:]), bin, signature.Signature[:]) {
		return false, errors.New("Invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey.PublicKey[:]), append(signature.Signature[:], []byte(signature.TrustedComment)[17:]...), signature.GlobalSignature[:]) {
		return false, errors.New("Invalid global signature")
	}
	return true, nil
}

func (publicKey *PublicKey) VerifyFromFile(file string, signature Signature) (bool, error) {
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return false, err
	}
	return publicKey.Verify(bin, signature)
}

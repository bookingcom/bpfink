package generic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"hash"
	"io"
	"os"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2b" // BLAKE2b hash
)

//Parser struct to handle parsing access.conf
type Parser struct {
	zerolog.Logger
	FileName string
	Hash     []byte
	Key      []byte
}

const nonceSize = 12

func defaultHashFunc() hash.Hash {
	h, _ := blake2b.New256(nil)
	return h
}

//Parse func that parses a access file to collect accessObjects
func (p *Parser) Parse() error {
	file, err := os.Open(p.FileName)
	if err != nil {
		p.Error().Err(err)
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			p.Error().Err(err)
		}
	}()
	p.Debug().Msgf("hashing file: %v", p.FileName)
	hash := defaultHashFunc()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	hashSum := hash.Sum(nil)

	nonce, err := generateNonce()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(p.Key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	p.Hash = append(nonce, aead.Seal(nil, nonce, hashSum, nil)...)
	p.Debug().Msgf("Hash: %v", string(p.Hash))
	return nil
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

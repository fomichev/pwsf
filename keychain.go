package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
)

// Keychain represents parsed PasswordSafe data file.
type Keychain struct {
	// Encrypted.

	salt [32]byte // Salt.
	pwd  [32]byte // SHA256 of expected stretched password.
	b12  [32]byte // 2 blocks that yield TwoFish key when decrypted.
	b34  [32]byte // 2 blocks that yield HMAC key when decrypted.
	iv   [16]byte // TwoFish CBC IV.
	iter uint32   // Number of password stretch iterations.
	data []byte   // Encrypted data.
	mac  []byte   // Expected HMAC.

	// Decrypted.

	Header *Item   // Header items (meta, ignored).
	Items  []*Item // Data items.
}

// NewKeychain parses on-disk representation of keychain and loads all
// encrypted data into memory.
func NewKeychain(path string) (*Keychain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var c Keychain
	if err := c.parseFile(f); err != nil {
		return nil, err
	}
	return &c, nil
}

// parseFile reads encrypted fields from file and fills in Keychain.
func (c *Keychain) parseFile(f *os.File) error {
	var tag [4]byte
	if _, err := io.ReadFull(f, tag[:]); err != nil {
		return err
	}

	if string(tag[:]) != "PWS3" {
		return fmt.Errorf("invalid tag %q", string(tag[:]))
	}

	if _, err := io.ReadFull(f, c.salt[:]); err != nil {
		return fmt.Errorf("can't read salt: %s", err)
	}

	var iter [4]byte
	if _, err := io.ReadFull(f, iter[:]); err != nil {
		return fmt.Errorf("can't read passsword stretch iterations: %s", err)
	}
	c.iter = binary.LittleEndian.Uint32(iter[0:4])

	if _, err := io.ReadFull(f, c.pwd[:]); err != nil {
		return fmt.Errorf("can't read hashed password: %s", err)
	}

	if _, err := io.ReadFull(f, c.b12[:]); err != nil {
		return fmt.Errorf("can't read B12: %s", err)
	}

	if _, err := io.ReadFull(f, c.b34[:]); err != nil {
		return fmt.Errorf("can't read B34: %s", err)
	}

	if _, err := io.ReadFull(f, c.iv[:]); err != nil {
		return fmt.Errorf("can't read B34: %s", err)
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("can't read data: %s", err)
	}

	eof := bytes.Index(data, []byte("PWS3-EOFPWS3-EOF"))
	if eof < 0 {
		return fmt.Errorf("EOF marker not found")
	}

	c.data = data[0:eof]
	if len(c.data)%16 != 0 {
		return fmt.Errorf("data is not block aligned")
	}

	c.mac = data[eof+16 : eof+16+32]
	return nil
}

// Unlock stretches password, decrypts the file and reads
// all decrypted items into memory.
func (c *Keychain) Unlock(pwd string) error {
	stretched := strechPassword(pwd, c.salt[:], c.iter)
	hashed := sha256.Sum256(stretched)
	if !bytes.Equal(c.pwd[:], hashed[:]) {
		return fmt.Errorf("invalid password")
	}

	var k, l [32]byte
	decryptECB(k[:], c.b12[:], stretched)
	decryptECB(l[:], c.b34[:], stretched)

	cleartext := make([]byte, len(c.data))
	decryptCBC(cleartext, c.data, k[:], c.iv[:])

	mac := hmac.New(sha256.New, l[:])
	if err := c.parseItems(bytes.NewBuffer(cleartext), mac); err != nil {
		return fmt.Errorf("can't parse items: %s", err)
	}

	if !hmac.Equal(mac.Sum(nil), c.mac) {
		return fmt.Errorf("can't verify HMAC")
	}

	return nil
}

// parseItems parses decrypted items from the cleartext.
func (c *Keychain) parseItems(r io.Reader, mac hash.Hash) error {
	// header
	h, err := ReadItem(r, mac)
	if err != nil {
		return fmt.Errorf("can't read header: %s", err)
	}

	c.Header = h
	c.Items = nil

	// data
	for {
		i, err := ReadItem(r, mac)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("can't read entry: %s", err)
		}
		c.Items = append(c.Items, i)
	}

	sort.Sort(ByName(c.Items))

	return nil
}

// Find returns a channel with the items matching RE in their title.
func (c *Keychain) Find(re string) chan *Item {
	ch := make(chan *Item)
	go func() {
		for _, f := range c.Items {
			matched, err := regexp.MatchString(re, f.String())
			if err != nil {
				panic(err)
			}
			if matched {
				ch <- f
			}
		}
		close(ch)
	}()
	return ch
}

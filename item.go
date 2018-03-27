package main

import (
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
)

// FieldType represents supported field types.
type FieldType int

const TypeEnd FieldType = 0xFF
const TypeGroup FieldType = 0x02
const TypeTitle FieldType = 0x03
const TypeUsername FieldType = 0x04
const TypeNotes FieldType = 0x05
const TypePassword FieldType = 0x06

// Field represents single property of an item (Username/Password/etc).
type Field struct {
	Type FieldType // Field type.
	data []byte    // Field raw data.
}

// ReadField parses field from the reader and updates HMAC.
func ReadField(r io.Reader, mac hash.Hash) (*Field, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[0:4]); err != nil {
		if err == io.EOF {
			// Don't wrap EOF so upper layer can see it.
			return nil, io.EOF
		}
		return nil, fmt.Errorf("can't read item length: %s", err)
	}
	ln := binary.LittleEndian.Uint32(buf[0:4])

	if _, err := io.ReadFull(r, buf[0:1]); err != nil {
		return nil, fmt.Errorf("can't read item tp: %s", err)
	}
	tp := buf[0]

	data := make([]byte, ln)
	if _, err := io.ReadFull(r, data[:]); err != nil {
		return nil, fmt.Errorf("can't read item data: %s", err)
	}

	// Fields are block-aligned (16 bytes), skip the remainder.
	padding := (5 + ln) % 16
	if padding != 0 {
		io.CopyN(ioutil.Discard, r, 16-int64(padding))
	}

	mac.Write(data)

	return &Field{FieldType(tp), data}, nil
}

// String returns string representation of the field value.
func (f *Field) String() string {
	if f == nil {
		return ""
	}
	return string(f.data)
}

// Item is a collection of fields (for example, single login
// entry contains triee fields: title, username and password.
type Item struct {
	Fields map[FieldType]*Field // Map of filed type to field.
}

type ByName []*Item

func (a ByName) Len() int           { return len(a) }
func (a ByName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByName) Less(i, j int) bool { return a[i].String() < a[j].String() }

// ReadItem parses item fields from the reader and updates HMAC.
func ReadItem(r io.Reader, mac hash.Hash) (*Item, error) {
	var i Item
	i.Fields = make(map[FieldType]*Field)

	for {
		f, err := ReadField(r, mac)
		if err != nil {
			if err == io.EOF && len(i.Fields) == 0 {
				// If the first thing we've found is EOF,
				// exit and return it so upper layer
				// can stop.
				return nil, io.EOF
			}
			return nil, err
		}
		if f.Type == TypeEnd {
			break
		}

		i.Fields[f.Type] = f
	}

	return &i, nil
}

// String returns full name of the item.
func (i *Item) String() string {
	if group, ok := i.Fields[TypeGroup]; ok {
		return fmt.Sprintf("%s.%s", group, i.Fields[TypeTitle])
	}
	return i.Fields[TypeTitle].String()
}

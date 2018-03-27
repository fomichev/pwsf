package main

import (
	"fmt"
	"testing"
)

func TestWrongPath(t *testing.T) {
	if _, err := NewKeychain("/invalid/path"); err == nil {
		t.Fatal("Didn't die on invalid keychain path")
	}
}

func TestWrongPassword(t *testing.T) {
	kc, err := NewKeychain("simple.psafe3")
	if err != nil {
		t.Fatal(err)
	}

	if err = kc.Unlock("invalid"); err == nil {
		t.Fatal("Didn't die on invalid keychain password")
	}
}

type ExpectedItem struct {
	Title string
	Items []map[FieldType]string
}

var expected = []ExpectedItem{
	{
		Title: "Test eight",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user8",
				TypePassword: "my password",
				TypeNotes:    "shift double click action set = run command",
			},
		},
	},
	{
		Title: "Test Four",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user4",
				TypePassword: "pass4",
			},
		},
	},
	{
		Title: "Test.Test One",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user2",
				TypePassword: "password2",
			},
			{
				TypeUsername: "user1",
				TypePassword: "password1",
			},
		},
	},
	{
		Title: "Test seven",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user7",
				TypePassword: "my password",
				TypeNotes:    "Symbols set for password generation",
			},
		},
	},
	{
		Title: "Test Two",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user3",
				TypePassword: "pass3",
			},
		},
	},
	{
		Title: "Test.Test Nine",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user9",
				TypePassword: "DoubleClickActionTest",
			},
		},
	},
	{
		Title: "Test six",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user6",
				TypePassword: "my password",
				TypeNotes:    "protected entry",
			},
		},
	},
	{
		Title: "Test Five",
		Items: []map[FieldType]string{
			{
				TypeUsername: "user5",
				TypePassword: "my password",
				TypeNotes:    "email address test",
			},
		},
	},
}

func TestUnlock(t *testing.T) {
	kc, err := NewKeychain("simple.psafe3")
	if err != nil {
		t.Fatal(err)
	}

	if err = kc.Unlock("bogus12345"); err != nil {
		t.Fatal(err)
	}

	if len(kc.Items) != 9 {
		t.Fatal("Invalid number of entries")
	}

	for _, e := range expected {
		nr := 0
		for i := range kc.Find(fmt.Sprintf("^%s$", e.Title)) {
			found := false
			for _, ei := range e.Items {
				if ei[TypeUsername] == i.Fields[TypeUsername].String() {

					for k, v := range ei {
						if i.Fields[k].String() != v {
							t.Fatalf("Unexpected %q != %q for %d in %s\n", i.Fields[k].String(), v, k, e.Title)
						}
					}

					found = true
					break
				}
			}
			if !found {
				t.Fatalf("Didn't find matching entry for %s\n", e.Title)
			}
			nr++
		}
		if len(e.Items) != nr {
			t.Fatalf("Unexpected number of items %d, expected %d with title %q\n", nr, len(e.Items), e.Title)
		}
	}
}

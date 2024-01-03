//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unicode/utf16"

	"github.com/danieljoos/wincred"
)

func run() error {
	creds, err := wincred.List()
	if err != nil {
		return fmt.Errorf("wincred list: %w", err)
	}

	for _, cred := range creds {
		credentialBlob, err := decodeUTF16LE(cred.CredentialBlob)
		if err != nil {
			credentialBlob = fmt.Sprintf("%q", string(cred.CredentialBlob))
		}

		fmt.Printf("%s:\n    * %s\n", cred.UserName, credentialBlob)
	}

	return nil
}

func decodeUTF16LE(d []byte) (string, error) {
	if len(d)%2 > 0 {
		return "", fmt.Errorf("UTF16LE requires even data length but actual length %d is uneven",
			len(d))
	}

	s := make([]uint16, len(d)/2)

	err := binary.Read(bytes.NewReader(d), binary.LittleEndian, &s)
	if err != nil {
		return "", err
	}

	return string(utf16.Decode(s)), nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}

package gob

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/essentialkaos/katana"
	"github.com/essentialkaos/katana/wrapper"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type GOBWrapper struct {
	skrt *katana.Secret
}

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrNilWrapper = fmt.Errorf("Wrapper is nil")
	ErrNoSecret   = fmt.Errorf("Wrapper has no secret")
	ErrEmptyData  = fmt.Errorf("Data is empty")
)

// ////////////////////////////////////////////////////////////////////////////////// //

// validate wrapper interface
var _ wrapper.Wrapper = (*GOBWrapper)(nil)

// ////////////////////////////////////////////////////////////////////////////////// //

// Wrap creates GOB wrapper
func Wrap(skrt *katana.Secret) *GOBWrapper {
	return &GOBWrapper{skrt}
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Encrypt encodes given object and encrypts data
func (w *GOBWrapper) Encrypt(v any) ([]byte, error) {
	switch {
	case w == nil:
		return nil, ErrNilWrapper
	case w.skrt == nil:
		return nil, ErrNoSecret
	}

	var buf bytes.Buffer

	err := gob.NewEncoder(&buf).Encode(v)

	if err != nil {
		return nil, err
	}

	return w.skrt.Encrypt(buf.Bytes())
}

// Decrypt decrypts given data and decodes it
func (w *GOBWrapper) Decrypt(data []byte, v any) error {
	switch {
	case w == nil:
		return ErrNilWrapper
	case w.skrt == nil:
		return ErrNoSecret
	case len(data) == 0:
		return ErrEmptyData
	}

	raw, err := w.skrt.Decrypt(data)

	if err != nil {
		return err
	}

	return gob.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

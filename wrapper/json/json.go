package json

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"encoding/json"
	"fmt"

	"github.com/essentialkaos/katana"
	"github.com/essentialkaos/katana/wrapper"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type Wrapper struct {
	skrt *katana.Secret
}

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrNilWrapper  = fmt.Errorf("Wrapper is nil")
	ErrNoSecret    = fmt.Errorf("Wrapper has no secret")
	ErrEmptyData   = fmt.Errorf("Data is empty")
	ErrEmptyObject = fmt.Errorf("Object is nil")
)

// ////////////////////////////////////////////////////////////////////////////////// //

// validate wrapper interface
var _ wrapper.Wrapper = (*Wrapper)(nil)

// ////////////////////////////////////////////////////////////////////////////////// //

// Wrap creates JSON wrapper
func Wrap(skrt *katana.Secret) *Wrapper {
	return &Wrapper{skrt}
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Encrypt encodes given object and encrypts data
func (w *Wrapper) Encrypt(v any) ([]byte, error) {
	switch {
	case w == nil:
		return nil, ErrNilWrapper
	case w.skrt == nil:
		return nil, ErrNoSecret
	case v == nil:
		return nil, ErrEmptyObject
	}

	raw, err := json.Marshal(v)

	if err != nil {
		return nil, err
	}

	return w.skrt.Encrypt(raw)
}

// Decrypt decrypts given data and decodes it
func (w *Wrapper) Decrypt(data []byte, v any) error {
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

	return json.Unmarshal(raw, v)
}

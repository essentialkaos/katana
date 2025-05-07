package wrapper

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2025 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

type Wrapper interface {
	// Encrypt encodes and encrypts given object
	Encrypt(data any) ([]byte, error)

	// Decrypt decrypts and decodes given data
	Decrypt(data []byte, v any) error
}

// ////////////////////////////////////////////////////////////////////////////////// //

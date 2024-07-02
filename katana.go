package katana

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//                       PRIVATE SOFTWARE, ALL RIGHTS RESERVED                        //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"

	"github.com/essentialkaos/sio"

	"github.com/essentialkaos/katana/secstr"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type File struct {
	fd   *os.File
	salt []byte
	cfg  sio.Config
	r    io.Reader
	w    io.WriteCloser
}

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrNilFile            = fmt.Errorf("File is nil")
	ErrEmptySecret        = fmt.Errorf("Secret is empty")
	ErrEmptySecretData    = fmt.Errorf("Secret data is empty")
	ErrEmptySecretPath    = fmt.Errorf("Secret path is empty")
	ErrEmptyEnvVarName    = fmt.Errorf("Environment variable name is empty")
	ErrEmptyEnvVar        = fmt.Errorf("Environment variable is empty")
	ErrAppendNotSupported = fmt.Errorf("Encrypted writer doesn't support O_APPEND flag")
)

// ////////////////////////////////////////////////////////////////////////////////// //

var secret *secstr.String

// ////////////////////////////////////////////////////////////////////////////////// //

// Add adds static part of the key
func Add(data string) error {
	if data == "" {
		return ErrEmptySecretData
	}

	return addKeyData([]byte(data))
}

// AddHex adds hex-encoded static part of the key
func AddHex(data string) error {
	if data == "" {
		return ErrEmptySecretData
	}

	bytes, err := hex.DecodeString(data)

	if err != nil {
		return fmt.Errorf("Can't decode hex-encoded secret data: %v", err)
	}

	return addKeyData(bytes)
}

// AddBase64 adds Base64-encoded static part of the key
func AddBase64(data string) error {
	if data == "" {
		return ErrEmptySecretData
	}

	bytes, err := base64.StdEncoding.DecodeString(data)

	if err != nil {
		return fmt.Errorf("Can't decode base64-encoded secret data: %v", err)
	}

	return addKeyData(bytes)
}

// AddEnv adds dynamic part of the key for environment variable
func AddEnv(name string) error {
	switch {
	case name == "":
		return ErrEmptyEnvVarName
	case os.Getenv(name) == "":
		return ErrEmptyEnvVar
	}

	Add(os.Getenv(name))

	err := os.Setenv(name, "")

	if err != nil {
		return fmt.Errorf("Can't clean secret from environment variable: %v", err)
	}

	return nil
}

// AddFile adds dynamic part of the key based on SHA-512 hash of the file
func AddFile(file string) error {
	if file == "" {
		return ErrEmptySecretPath
	}

	fd, err := os.OpenFile(file, os.O_RDONLY, 0)

	if err != nil {
		return fmt.Errorf("Can't open file %q: %v", file, err)
	}

	defer fd.Close()

	hasher := sha512.New()
	_, err = io.Copy(hasher, fd)

	if err != nil {
		return fmt.Errorf("Can't calculate file %q hash: %v", file, err)
	}

	return addKeyData(hasher.Sum(nil))
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Open opens the named file for reading. If successful, methods on the returned file
// can be used for reading; the associated file descriptor has mode O_RDONLY.
func Open(name string) (*File, error) {
	if secret.IsEmpty() {
		return nil, ErrEmptySecret
	}

	key, salt, err := deriveKey(name)

	if err != nil {
		return nil, err
	}

	fd, err := os.Open(name)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %v", err)
	}

	return &File{fd: fd, cfg: sio.Config{Key: key}, salt: salt}, nil
}

// OpenFile opens the named file with specified flag (O_RDONLY etc.). If the file does
// not exist, and the O_CREATE flag is passed, it is created with mode perm (before
// umask).
func OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	switch {
	case secret.IsEmpty():
		return nil, ErrEmptySecret
	case flag&os.O_APPEND != 0:
		return nil, ErrAppendNotSupported
	}

	key, salt, err := deriveKey(name)

	if err != nil {
		return nil, err
	}

	fd, err := os.OpenFile(name, flag, perm)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %v", err)
	}

	return &File{fd: fd, cfg: sio.Config{Key: key}, salt: salt}, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Name returns the name of the file as presented to Open
func (f *File) Name() string {
	if f == nil || f.fd == nil {
		return ""
	}

	return f.fd.Name()
}

// Stat returns the FileInfo structure describing file
func (f *File) Stat() (os.FileInfo, error) {
	if f == nil || f.fd == nil {
		return nil, ErrNilFile
	}

	return f.fd.Stat()
}

// Chmod changes the mode of the file to mode
func (f *File) Chmod(mode os.FileMode) error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	return f.fd.Chmod(mode)
}

// Chown changes the numeric uid and gid of the named file
func (f *File) Chown(uid, gid int) error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	return f.fd.Chown(uid, gid)
}

// Close closes the File, rendering it unusable for I/O
func (f *File) Close() error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	var err error

	// Close underlay text writer
	if f.w != nil {
		err = f.w.Close()
	} else {
		err = f.fd.Close()
	}

	// Clean key data
	if len(f.cfg.Key) > 0 {
		clearByteSlice(f.cfg.Key)
	}

	return err
}

// String returns string representation of File
func (f *File) String() string {
	if f == nil || f.fd == nil {
		return "&katana.File{nil}"
	}

	return fmt.Sprintf("&katana.File{%s}", f.fd.Name())
}

// Write writes len(b) bytes from b to the File
func (f *File) Write(b []byte) (int, error) {
	if f == nil || f.fd == nil {
		return 0, ErrNilFile
	}

	var err error

	if len(f.salt) > 0 {
		_, err = f.fd.Write(f.salt)

		if err != nil {
			return 0, fmt.Errorf("Can't write salt into file: %v", err)
		}

		f.salt = nil
	}

	// Lazy writer initialization
	if f.w == nil {
		f.w, err = sio.EncryptWriter(f.fd, f.cfg)

		if err != nil {
			return 0, fmt.Errorf("Can't create encrypted writer: %v", err)
		}
	}

	return f.w.Write(b)
}

// Read reads up to len(b) bytes from the File and stores them in b
func (f *File) Read(b []byte) (int, error) {
	if f == nil || f.fd == nil {
		return 0, ErrNilFile
	}

	var err error

	// Lazy reader initialization
	if f.r == nil {
		// Skip salt bytes
		f.fd.Seek(32, io.SeekStart)

		f.r, err = sio.DecryptReader(f.fd, f.cfg)

		if err != nil {
			return 0, fmt.Errorf("Can't create encrypted reader: %v", err)
		}
	}

	return f.r.Read(b)
}

// ////////////////////////////////////////////////////////////////////////////////// //

// deriveKey creates derived key from secret
func deriveKey(file string) ([]byte, []byte, error) {
	salt, hasSalt := make([]byte, 32), false
	fd, err := os.OpenFile(file, os.O_RDONLY, 0)

	if err != nil {
		if os.IsNotExist(err) {
			_, err = io.ReadFull(rand.Reader, salt)

			if err != nil {
				return nil, nil, fmt.Errorf("Can't generate random salt: %v", err)
			}
		} else {
			return nil, nil, err
		}
	} else {
		defer fd.Close()

		info, err := fd.Stat()

		if err != nil {
			return nil, nil, fmt.Errorf("Can't read file info: %v", err)
		}

		if info.Size() == 0 {
			_, err = io.ReadFull(rand.Reader, salt)

			if err != nil {
				return nil, nil, fmt.Errorf("Can't generate random salt: %v", err)
			}
		} else {
			_, err := io.ReadFull(fd, salt)

			if err != nil {
				return nil, nil, fmt.Errorf("Can't read salt from file: %v", err)
			}

			hasSalt = true
		}
	}

	key, err := scrypt.Key(secret.Data, salt, 32768, 16, 1, 32)

	if err != nil {
		return nil, nil, fmt.Errorf("Can't derive key from secret: %v", err)
	}

	if hasSalt {
		return key, nil, nil
	}

	return key, salt, nil
}

// addKeyData adds key data
func addKeyData(data []byte) error {
	var err error

	if secret == nil {
		secret, err = secstr.NewSecureString(data)

		if err != nil {
			return fmt.Errorf("Can't create secure string: %v", err)
		}
	} else {
		secret.Data = append(secret.Data, data...)
	}

	return nil
}

// clearByteSlice clears byte slice
func clearByteSlice(s []byte) {
	for i := range s {
		s[i] = 0
	}
}

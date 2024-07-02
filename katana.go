package katana

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
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

type Secret struct {
	pwd *secstr.String
	err error
}

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
	ErrNilSecret          = fmt.Errorf("Secret is nil")
	ErrEmptySecret        = fmt.Errorf("Secret is empty")
	ErrEmptySecretData    = fmt.Errorf("Secret data is empty")
	ErrEmptySecretPath    = fmt.Errorf("Secret path is empty")
	ErrEmptyEnvVarName    = fmt.Errorf("Environment variable name is empty")
	ErrEmptyEnvVar        = fmt.Errorf("Environment variable is empty")
	ErrAppendNotSupported = fmt.Errorf("Encrypted writer doesn't support O_APPEND flag")
)

// ////////////////////////////////////////////////////////////////////////////////// //

// NewSecret creates new katana secret
func NewSecret(data string) *Secret {
	s := &Secret{}
	return s.Add(data)
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Add adds static part of the key
func (s *Secret) Add(data string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case data == "":
		s.err = ErrEmptySecretData
		return s
	}

	s.err = s.addKeyData([]byte(data))

	return s
}

// AddHex adds hex-encoded static part of the key
func (s *Secret) AddHex(data string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case data == "":
		s.err = ErrEmptySecretData
		return s
	}

	bytes, err := hex.DecodeString(data)

	if err != nil {
		s.err = err
		return s
	}

	s.err = s.addKeyData(bytes)

	return s
}

// AddBase64 adds Base64-encoded static part of the key
func (s *Secret) AddBase64(data string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case data == "":
		s.err = ErrEmptySecretData
		return s
	}

	bytes, err := base64.StdEncoding.DecodeString(data)

	if err != nil {
		s.err = err
		return s
	}

	s.err = s.addKeyData(bytes)

	return s
}

// AddEnv adds dynamic part of the key for environment variable
func (s *Secret) AddEnv(name string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case name == "":
		s.err = ErrEmptyEnvVarName
		return s
	case os.Getenv(name) == "":
		s.err = ErrEmptyEnvVar
		return s
	}

	s.err = s.addKeyData([]byte(os.Getenv(name)))

	err := os.Setenv(name, "")

	if err != nil {
		s.err = fmt.Errorf("Can't clean secret from environment variable: %v", err)
		return s
	}

	return s
}

// AddFile adds dynamic part of the key based on SHA-512 hash of the file
func (s *Secret) AddFile(file string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case file == "":
		s.err = ErrEmptySecretPath
		return s
	}

	fd, err := os.OpenFile(file, os.O_RDONLY, 0)

	if err != nil {
		s.err = fmt.Errorf("Can't open file %q: %v", file, err)
		return s
	}

	hasher := sha512.New()
	_, err = io.Copy(hasher, fd)

	if err != nil {
		s.err = fmt.Errorf("Can't calculate file %q hash: %v", file, err)
		return s
	}

	s.err = s.addKeyData(hasher.Sum(nil))

	return s
}

// Validate validates secret
func (s *Secret) Validate() error {
	switch {
	case s == nil:
		return ErrNilSecret
	case s.err != nil:
		return s.err
	case s.pwd.IsEmpty():
		return ErrEmptySecretData
	}

	return nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Open opens the named file for reading. If successful, methods on the returned file
// can be used for reading; the associated file descriptor has mode O_RDONLY.
func (s *Secret) Open(name string) (*File, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	key, salt, err := s.deriveKey(name)

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
func (s *Secret) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	if flag&os.O_APPEND != 0 {
		return nil, ErrAppendNotSupported
	}

	key, salt, err := s.deriveKey(name)

	if err != nil {
		return nil, err
	}

	fd, err := os.OpenFile(name, flag, perm)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %v", err)
	}

	return &File{fd: fd, cfg: sio.Config{Key: key}, salt: salt}, nil
}

// ReadFile reads the named file and returns the contents
func (s *Secret) ReadFile(name string) ([]byte, error) {
	f, err := s.Open(name)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	return io.ReadAll(f)
}

// WriteFile writes data to the named file, creating it if necessary
func (s *Secret) WriteFile(name string, data []byte, perm os.FileMode) error {
	f, err := s.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)

	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(data)

	return err
}

// ////////////////////////////////////////////////////////////////////////////////// //

// addKeyData appends key data
func (s *Secret) addKeyData(data []byte) error {
	var err error

	if s.pwd == nil {
		s.pwd, err = secstr.NewSecureString(data)

		if err != nil {
			return fmt.Errorf("Can't create secure string: %v", err)
		}
	} else {
		defer s.pwd.Destroy()

		s.pwd, err = secstr.NewSecureString(append(s.pwd.Data, data...))

		if err != nil {
			return fmt.Errorf("Can't create secure string: %v", err)
		}
	}

	return nil
}

// deriveKey creates derived key from secret
func (s *Secret) deriveKey(file string) ([]byte, []byte, error) {
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

	secretData := append([]byte{}, s.pwd.Data...)
	key, err := scrypt.Key(secretData, salt, 32768, 16, 1, 32)

	if err != nil {
		return nil, nil, fmt.Errorf("Can't derive key from secret: %v", err)
	}

	if hasSalt {
		return key, nil, nil
	}

	return key, salt, nil
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

// clearByteSlice clears byte slice
func clearByteSlice(s []byte) {
	for i := range s {
		s[i] = 0
	}
}

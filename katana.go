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
)

// ////////////////////////////////////////////////////////////////////////////////// //

const SALT_SIZE = 32

// ////////////////////////////////////////////////////////////////////////////////// //

// Secret is katana secret storage
type Secret struct {
	pwd []byte
	err error
}

// Reader is encrypted data reader
type Reader struct {
	secret    *Secret
	rawReader io.Reader
	decReader io.Reader
}

// Reader is encrypted data writer
type Writer struct {
	secret    *Secret
	rawWriter io.WriteCloser
	encWriter io.WriteCloser
}

// File represents encrypted file
type File struct {
	secret *Secret
	fd     *os.File
	r      *Reader
	w      *Writer
}

// Checksum is secret checksum
type Checksum []byte

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrNilFile         = fmt.Errorf("File is nil")
	ErrNilSecret       = fmt.Errorf("Secret is nil")
	ErrEmptySecret     = fmt.Errorf("Secret is empty")
	ErrEmptySecretData = fmt.Errorf("Secret data is empty")
	ErrEmptySecretPath = fmt.Errorf("Secret path is empty")
	ErrEmptyEnvVarName = fmt.Errorf("Environment variable name is empty")
	ErrEmptyEnvVar     = fmt.Errorf("Environment variable is empty")
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

	s.addKeyData([]byte(data))

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

	s.addKeyData(bytes)

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

	s.addKeyData(bytes)

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

	s.addKeyData([]byte(os.Getenv(name)))

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

	s.addKeyData(hasher.Sum(nil))

	return s
}

// Validate validates secret
func (s *Secret) Validate() error {
	switch {
	case s == nil:
		return ErrNilSecret
	case s.err != nil:
		return s.err
	case len(s.pwd) == 0:
		return ErrEmptySecretData
	}

	return nil
}

// Checksum returns secret checksum
func (s *Secret) Checksum() Checksum {
	if s == nil || s.pwd == nil || len(s.pwd) == 0 {
		return nil
	}

	hasher := sha512.New512_256()
	hasher.Write(s.pwd)

	return Checksum(hasher.Sum(nil))
}

// String returns string representation of secret
func (s *Secret) String() string {
	return fmt.Sprintf("katana.Secret{%s}", s.Checksum().Short())
}

// ////////////////////////////////////////////////////////////////////////////////// //

// String returns full checksum as string
func (c Checksum) String() string {
	if len(c) != 32 {
		return ""
	}

	return fmt.Sprintf("%064x", []byte(c))
}

// Short returns short checksum (first 7 bytes)
func (c Checksum) Short() string {
	if len(c) != 32 {
		return ""
	}

	return c.String()[:7]
}

// ////////////////////////////////////////////////////////////////////////////////// //

// NewReader creates new reader instance
func (s *Secret) NewReader(r io.Reader) (*Reader, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	return &Reader{secret: s, rawReader: r}, nil
}

// NewWriter creates new writer instance
func (s *Secret) NewWriter(w io.WriteCloser) (*Writer, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	return &Writer{secret: s, rawWriter: w}, nil
}

// Open opens the named file for reading. If successful, methods on the returned file
// can be used for reading; the associated file descriptor has mode O_RDONLY.
func (s *Secret) Open(name string) (*File, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	fd, err := os.Open(name)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %v", err)
	}

	return &File{secret: s, fd: fd}, nil
}

// OpenFile opens the named file with specified flag (O_RDONLY etc.). If the file does
// not exist, and the O_CREATE flag is passed, it is created with mode perm (before
// umask).
func (s *Secret) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	switch {
	case flag&os.O_APPEND != 0:
		return nil, fmt.Errorf("Can't open file %q: Unsupported flag O_APPEND", name)
	case flag&os.O_RDWR != 0:
		return nil, fmt.Errorf("Can't open file %q: Unsupported flag O_RDWR", name)
	}

	fd, err := os.OpenFile(name, flag, perm)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %v", err)
	}

	return &File{secret: s, fd: fd}, nil
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
	f, err := s.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)

	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(data)

	return err
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Read reads and decrypts data
func (r *Reader) Read(p []byte) (n int, err error) {
	if r.decReader != nil {
		return r.decReader.Read(p)
	}

	// read the first 32 bytes with salt
	salt := make([]byte, SALT_SIZE)
	_, err = io.ReadFull(r.rawReader, salt)

	if err != nil {
		return 0, fmt.Errorf("Can't read salt: %w", err)
	}

	key, _, err := deriveKey(r.secret.pwd, salt)

	if err != nil {
		return 0, fmt.Errorf("Error while key generation: %w", err)
	}

	r.decReader, err = sio.DecryptReader(r.rawReader, sio.Config{
		Key:          key,
		CipherSuites: []byte{sio.CHACHA20_POLY1305},
	})

	if err != nil {
		return 0, fmt.Errorf("Can't create decrypt reader: %w", err)
	}

	return r.decReader.Read(p)
}

// String returns string representation of reader
func (r *Reader) String() string {
	if r == nil || r.decReader == nil {
		return "katana.Reader{nil}"
	}

	return "katana.Reader{}"
}

// Write encrypts and writes data
func (w *Writer) Write(p []byte) (n int, err error) {
	if w.encWriter != nil {
		return w.encWriter.Write(p)
	}

	key, salt, err := deriveKey(w.secret.pwd, nil)

	if err != nil {
		return 0, fmt.Errorf("Error while key generation: %w", err)
	}

	// write salt to the beginning of the file
	_, err = w.rawWriter.Write(salt)

	if err != nil {
		return 0, fmt.Errorf("Error while writing salt: %w", err)
	}

	w.encWriter, err = sio.EncryptWriter(w.rawWriter, sio.Config{
		Key:          key,
		CipherSuites: []byte{sio.CHACHA20_POLY1305},
	})

	if err != nil {
		return 0, fmt.Errorf("Can't create encrypt writer: %w", err)
	}

	return w.encWriter.Write(p)
}

// Close closes writer
func (w *Writer) Close() error {
	return w.encWriter.Close()
}

// String returns string representation of writer
func (w *Writer) String() string {
	if w == nil || w.encWriter == nil {
		return "katana.Writer{nil}"
	}

	return "katana.Writer{}"
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Write writes len(b) bytes from b to the File
func (f *File) Write(b []byte) (int, error) {
	if f == nil || f.fd == nil {
		return 0, ErrNilFile
	}

	if f.w != nil {
		return f.w.Write(b)
	}

	var err error

	f.w, err = f.secret.NewWriter(f.fd)

	if err != nil {
		return 0, err
	}

	return f.w.Write(b)
}

// Read reads up to len(b) bytes from the File and stores them in b
func (f *File) Read(b []byte) (int, error) {
	if f == nil || f.fd == nil {
		return 0, ErrNilFile
	}

	if f.r != nil {
		return f.r.Read(b)
	}

	var err error

	f.r, err = f.secret.NewReader(f.fd)

	if err != nil {
		return 0, err
	}

	return f.r.Read(b)
}

// Close closes the File, rendering it unusable for I/O
func (f *File) Close() error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	var err error

	// Close underlay writer
	if f.w != nil {
		err = f.w.Close()
	} else {
		err = f.fd.Close()
	}

	f.secret = nil

	return err
}

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

// String returns string representation of File
func (f *File) String() string {
	if f == nil || f.fd == nil {
		return "&katana.File{nil}"
	}

	return fmt.Sprintf("&katana.File{%s}", f.fd.Name())
}

// ////////////////////////////////////////////////////////////////////////////////// //

// addKeyData appends key data
func (s *Secret) addKeyData(data []byte) {
	s.pwd = append(s.pwd, data...)

	for i := range data {
		data[i] = 0
	}
}

// ////////////////////////////////////////////////////////////////////////////////// //

// deriveKey creates derived key from secret and salt
func deriveKey(key, salt []byte) ([]byte, []byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, SALT_SIZE)
		io.ReadFull(rand.Reader, salt)
	}

	keyData, err := scrypt.Key(key, salt, 32768, 16, 1, SALT_SIZE)

	if err != nil {
		return nil, salt, err
	}

	return keyData, salt, nil
}

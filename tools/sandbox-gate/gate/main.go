package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const releasePath = "/.grapefuit-sandbox/release"

func arguments(args []string) (string, []string, error) {
	if len(args) < 6 || args[0] != "--release" || args[1] != releasePath || args[2] != "--token" || args[4] != "--" {
		return "", nil, errors.New("invalid gate arguments")
	}
	token := args[3]
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 || token != fmt.Sprintf("%x", decoded) || args[5] == "" {
		return "", nil, errors.New("invalid gate token or command")
	}
	return token, args[5:], nil
}

func waitRelease(path, token string, deadline time.Time) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	waiting := []byte("0" + token + "\n")
	opened := []byte("1" + token + "\n")
	for {
		metadata, err := file.Stat()
		if err != nil || !metadata.Mode().IsRegular() || metadata.Size() != 66 {
			return errors.New("invalid gate release file")
		}
		var buffer [67]byte
		n, err := file.ReadAt(buffer[:], 0)
		if n != 66 || (err != nil && err != io.EOF) {
			return errors.New("invalid gate release contents")
		}
		if bytes.Equal(buffer[:n], opened) {
			return nil
		}
		if !bytes.Equal(buffer[:n], waiting) {
			return errors.New("gate release identity changed")
		}
		if !time.Now().Before(deadline) {
			return errors.New("gate release deadline exceeded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func run(args []string) error {
	token, command, err := arguments(args)
	if err != nil {
		return err
	}
	if err := waitRelease(releasePath, token, time.Now().Add(5*time.Minute)); err != nil {
		return err
	}
	program, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	return syscall.Exec(program, command, os.Environ())
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox gate:", err)
		os.Exit(125)
	}
}

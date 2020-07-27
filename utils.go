package main

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"net/http"
)

func calcMD5(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	md5 := md5.New()
	_, err = io.Copy(md5, file)
	if err != nil {
		return "", err
	}
	md5str := hex.EncodeToString(md5.Sum(nil))
	return md5str, nil
}

func download(url string, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return err
}

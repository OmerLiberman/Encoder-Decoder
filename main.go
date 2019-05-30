package main

import "os"

func main() {
	if os.Args[1] == "Encrypt" {
		toEncrypt := os.Args[2]
		useEncoder(toEncrypt)
	}

	if os.Args[1] == "Decrypt" {
		h0File, toEncrypt := os.Args[2], os.Args[3]
		useDecoder(h0File, toEncrypt)
	} else {
		panic("Usage: 1) Encrypt <to_encrypt_file_path> \n 2) Decrypt <h0_file> <encrypted_data_file_path>")
	}
}

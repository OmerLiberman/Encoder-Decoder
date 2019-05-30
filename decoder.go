package main

import (
	"crypto/sha256"
	"io/ioutil"
	"log"
)

// BlockSizeDec - the size of block + his encryption
const BlockSizeDec = 1056

func compareSlices(slc []byte, arr [32]byte) bool {
	for i := 0; i < len(arr); i++ {
		if slc[i] != arr[i] {
			return false
		}
	}
	return true
}

func decoder(h0 string, data []byte) []byte {
	encryptedData := make([]byte, 0)

	temp := make([]byte, 0)
	copy(data, temp)

	// Compare first block :
	currentBlock := temp[:BlockSizeDec]
	temp = temp[BlockSizeDec:]
	hexOfBlock := getHex(currentBlock)
	if h0 != hexOfBlock {
		panic("Unmatch found!")
	}
	decryptedBlock, prevH := currentBlock[:BlockSize], currentBlock[BlockSize:]
	encryptedData = append(encryptedData, decryptedBlock...)

	lenOfRestEncryptedData := len(temp)
	for lenOfRestEncryptedData > 0 {
		currentBlock = temp[:BlockSizeDec]
		shaOfBlock := sha256.Sum256(currentBlock)

		if compareSlices(prevH, shaOfBlock) {
			panic("Unmantch found!")
		}

		decryptedBlock, prevH = currentBlock[:BlockSize], currentBlock[BlockSize:]
		encryptedData = append(encryptedData, decryptedBlock...)

		temp = temp[BlockSizeDec:]
		lenOfRestEncryptedData -= BlockSizeDec
	}

	return encryptedData
}

func useDecoder(filePathH, filePathData string) {
	h0File, encryptedDataFile := filePathH, filePathData

	stream, err := ioutil.ReadFile(h0File)
	if err != nil {
		log.Fatal(err)
	}
	h0 := string(stream)

	d, err := ioutil.ReadFile(encryptedDataFile)
	if err != nil {
		log.Fatal(err)
	}
	data := d

	decrypted := decoder(h0, data)
	ioutil.WriteFile("DecryptedData.txt", decrypted, 0777)
}

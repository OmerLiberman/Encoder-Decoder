package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math"
	"os"
)

// BlockSize - The size of blocks to divide the input
const BlockSize = 1024

func getNumOfBlocks(lengthOfData int) int {
	avgSizeOfBlock := float64(lengthOfData / BlockSize)
	return int(math.Floor(avgSizeOfBlock))
}

func getSizeOfLastBlock(lengthOfData int) int {
	if lengthOfData%BlockSize == 0 {
		return BlockSize
	}
	return lengthOfData % BlockSize

}

func getLastPartShouldBeEncrypted(data []byte, sizeOfBlock int) ([]byte, []byte) {
	/*
		This method splits the given data to:
		one block which is the last "sizeOfBlock" bytes, and the rest of the data.
		FOR THE USER : the rest is returned first, then the last block.
	*/
	lenOfData := len(data)
	lenOfDataRemainsAfterSplitting := lenOfData - sizeOfBlock
	return data[:lenOfDataRemainsAfterSplitting], data[lenOfDataRemainsAfterSplitting:]
}

func encryptBlock(blockToEncrypt []byte) []byte {
	shaOfBlock := sha256.Sum256(blockToEncrypt)
	return shaOfBlock[:]
}

func getLengthOfAllSlices(slices [][]byte) int {
	toReturn := 0
	for i := 0; i < len(slices); i++ {
		toReturn += len(slices[i])
	}
	return toReturn
}

func reverseOrder(toBeReversed [][]byte) []byte {
	for i := 0; i < len(toBeReversed)/2; i++ {
		j := len(toBeReversed) - i - 1
		toBeReversed[i], toBeReversed[j] = toBeReversed[j], toBeReversed[i]
	}
	toReturn := make([]byte, getLengthOfAllSlices(toBeReversed))
	for i := 0; i < len(toBeReversed); i++ {
		toReturn = append(toReturn, toBeReversed[i]...)
	}
	return toReturn
}

func getHex(blockToBeHaxed []byte) string {
	return hex.EncodeToString(blockToBeHaxed)
}

func encoder(data []byte) (string, []byte) {
	tmpData := make([]byte, len(data))
	copy(tmpData, data)
	arrayOfBlocks, arrayOfH := make([][]byte, 0), make([][]byte, 0)

	// Encrypt last block.
	sizeOfLastBlock := getSizeOfLastBlock(len(data))
	tmpData, blockToEncrypt := getLastPartShouldBeEncrypted(tmpData, sizeOfLastBlock)
	encryptOfLastBlock := encryptBlock(blockToEncrypt)
	arrayOfBlocks = append(arrayOfBlocks, blockToEncrypt)
	arrayOfH = append(arrayOfH, encryptOfLastBlock)

	// Encrypt the rest of data
	lenOfRestData := len(tmpData)
	for lenOfRestData > 0 {
		lenOfDataRemainsAfterSplitting := len(tmpData) - BlockSize

		blockToEncrypt := tmpData[lenOfDataRemainsAfterSplitting:]
		blockToEncrypt = append(blockToEncrypt, arrayOfH[len(arrayOfH)-1]...)

		encryptOfLastBlock := encryptBlock(blockToEncrypt)

		arrayOfBlocks = append(arrayOfBlocks, blockToEncrypt)
		arrayOfH = append(arrayOfH, encryptOfLastBlock)
		lenOfRestData -= BlockSize
		tmpData = tmpData[:lenOfDataRemainsAfterSplitting]
	}

	hexOfH0 := getHex(encryptBlock(arrayOfBlocks[len(arrayOfBlocks)-1]))
	reverseOrder(arrayOfBlocks)
	encryptedData := make([]byte, 0)
	for i := 0; i < len(arrayOfBlocks); i++ {
		encryptedData = append(encryptedData, arrayOfBlocks[i]...)
	}

	return hexOfH0, encryptedData
}

func useEncoder(fileToEncrypt string) {

	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	h0, encrypted := encoder(data)
	ioutil.WriteFile("EncryptedData.txt", encrypted, 0777)
	file, err := os.Create("h0.txt")
	if err != nil {
		log.Fatal(err)
	}
	file.WriteString(h0)
	file.Close()
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math"
	"os"
)

// -------------------- Encoder -------------------- //

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

func getHex(blockToBeHexed []byte) string {
	return hex.EncodeToString(blockToBeHexed)
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

	data, err := ioutil.ReadFile(fileToEncrypt)
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


// -------------------- Decoder -------------------- //

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

	temp := make([]byte, len(data))
	copy(data, temp)

	// Compare first block :
	currentBlock := temp[:BlockSizeDec]
	temp = temp[BlockSizeDec:]
	hexOfBlock := getHex(encryptBlock(currentBlock))
	if h0 != hexOfBlock {
		panic("Un match found ! The h0 is incorrect!")
	}
	decryptedBlock, prevH := currentBlock[:BlockSize], currentBlock[BlockSize:]
	encryptedData = append(encryptedData, decryptedBlock...)

	lenOfRestEncryptedData := len(temp)
	for lenOfRestEncryptedData > 0 {
		currentBlock = temp[:BlockSizeDec]
		shaOfBlock := sha256.Sum256(currentBlock)

		if compareSlices(prevH, shaOfBlock) {
			panic("Un match found! One of the blocks doesn't match!")
		}

		decryptedBlock, prevH = currentBlock[:BlockSize], currentBlock[BlockSize:]
		encryptedData = append(encryptedData, decryptedBlock...)

		temp = temp[BlockSizeDec:]
		lenOfRestEncryptedData -= BlockSizeDec
	}

	return encryptedData
}

func useDecoder(filePathH0 string, filePathEncodedData string) {

	stream, err := ioutil.ReadFile(filePathH0)
	if err != nil {
		log.Fatal(err)
	}
	h0 := string(stream)

	d, err := ioutil.ReadFile(filePathEncodedData)
	if err != nil {
		log.Fatal(err)
	}
	data := d

	decrypted := decoder(h0, data)
	ioutil.WriteFile("DecryptedData.txt", decrypted, 0777)
}


// -------------------- Main -------------------- //

func main() {
	// // Creating file of zero bytes :
	zero := make([]byte, 10000)
	ioutil.WriteFile("fileOfZeros.txt", zero, 0777)

	// // Encode file :
	addressOfFileToEncrypt := "C:\\Users\\Omer Liberman\\Desktop\\intuit_challenge2\\fileOfZeros.txt"
	useEncoder(addressOfFileToEncrypt)

	// // Decode file :
	h0File := "C:\\Users\\Omer Liberman\\Desktop\\intuit_challenge2\\h0.txt"
	encryptedFile := "C:\\Users\\Omer Liberman\\Desktop\\intuit_challenge2\\EncryptedData.txt"
	useDecoder(h0File, encryptedFile)

	// // The regular main :
	//if os.Args[1] == "Encrypt" {
	//	toEncrypt := os.Args[2]
	//	useEncoder(toEncrypt)
	//}
	//
	//if os.Args[1] == "Decrypt" {
	//	h0File, toEncrypt := os.Args[2], os.Args[3]
	//	useDecoder(h0File, toEncrypt)
	//} else {
	//	panic("Usage: 1) Encrypt <to_encrypt_file_path> \n              2) Decrypt <h0_file> <encrypted_data_file_path>")
	//}
}

package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"crypto/aes"
	"crypto/rsa"

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username string
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	Password string
	Key      *rsa.PrivateKey
	FileKey  map[string]uuid.UUID
	//SharingRecords []sharingRecord
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	fileUUID := uuid.New()
	userdata.FileKey[filename] = fileUUID

	var record sharingRecord
	record.FileID = fileUUID
	record.UserNames = append(record.UserNames, userdata.Username)
	sharingdata, err := json.Marshal(record)
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)
	userlib.DatastoreSet(sharingkey[:8], sharingdata) //Store record using key as first 8 Bytes of fileUUID

	if (len(data) % configBlockSize) != 0 {
		err := errors.New("Invalid Data Size")
		return err
	}

	hmac := userlib.NewHMAC(sharingdata)
	hashkey := hmac.Sum(nil) //Hash key is used to store indirectInode

	iv := make([]byte, aes.BlockSize)
	iv = userlib.RandomBytes(aes.BlockSize)

	aesCypherStream := userlib.CFBEncrypter([]byte(sharingkey), iv) //FileUUID is used as Encryption key

	//FileUUID will be shared as message among Users

	encryptedData := make([]byte, len(data))
	aesCypherStream.XORKeyStream(encryptedData, data)
	mac := userlib.NewHMAC([]byte(sharingkey)) //Create HMAC
	mac.Write(encryptedData)

	inodeIndirect := []uuid.UUID{}
	firstInode := true
	remainingLength := len(encryptedData)
	start := 0
	end := configBlockSize
	for {
		inode := []uuid.UUID{}
		inodeUUID := uuid.New()
		inodeIndirect = append(inodeIndirect, inodeUUID)
		if firstInode {
			ivUUID := uuid.New()
			inode = append(inode, ivUUID)
			userlib.DatastoreSet(ivUUID.String(), iv)
			firstInode = false
		}

		//countUUID := configBlockSize / 32	//calculating max number of UUID in a block
		for len(inode)*16 < configBlockSize {
			if remainingLength == 0 {
				break
			}
			id := uuid.New()
			inode = append(inode, id)
			userlib.DatastoreSet(id.String(), encryptedData[start:end])
			start += configBlockSize
			end += configBlockSize
			remainingLength -= configBlockSize
		}

		if remainingLength == 0 {
			macUUID := uuid.New()
			hmacBlock := mac.Sum(nil)
			inode = append(inode, macUUID)
			userlib.DatastoreSet(macUUID.String(), hmacBlock)
			encodedInode, _ := json.Marshal(inode)
			userlib.DatastoreSet(inodeUUID.String(), encodedInode)
			break
		}

		encodedInode, _ := json.Marshal(inode)
		userlib.DatastoreSet(inodeUUID.String(), encodedInode)
	}

	encodedIndirectnode, _ := json.Marshal(inodeIndirect)
	userlib.DatastoreSet(string(hashkey), encodedIndirectnode)

	return
}

// AppendFile :should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	oldData, _ := userdata.LoadFile(filename, 0) //Getting whole file for HMAC verification
	//Get old encrypted data
	fileUUID := userdata.FileKey[filename]
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)
	sharingdata, _ := userlib.DatastoreGet(sharingkey[:8])

	hmac := userlib.NewHMAC(sharingdata)
	hashkey := hmac.Sum(nil)
	inodeIndirect := []uuid.UUID{}
	encodedIndirectInode, _ := userlib.DatastoreGet(string(hashkey))
	if err := json.Unmarshal(encodedIndirectInode, &inodeIndirect); err != nil {
		panic(err)
	}

	inodeID := inodeIndirect[len(inodeIndirect)-1]
	inode := []uuid.UUID{}
	encodedInode, _ := userlib.DatastoreGet(inodeID.String())
	if err := json.Unmarshal(encodedInode, &inode); err != nil {
		panic(err)
	}
	oldIvID := inode[0]
	oldIV, _ := userlib.DatastoreGet(oldIvID.String())
	aesCypherStream := userlib.CFBEncrypter([]byte(sharingkey), oldIV) //FileUUID is used as Encryption key
	oldEncryptedData := make([]byte, len(oldData))
	aesCypherStream.XORKeyStream(oldEncryptedData, oldData)

	iv := oldEncryptedData[len(oldEncryptedData)-aes.BlockSize:] //Using last aesBlock as iv to new file

	aesCypherStreamNew := userlib.CFBEncrypter([]byte(sharingkey), iv) //FileUUID is used as Encryption key
	newEncryptedData := make([]byte, len(data))
	aesCypherStreamNew.XORKeyStream(newEncryptedData, data)

	wholeData := append(oldEncryptedData, newEncryptedData...)
	newHmac := userlib.NewHMAC([]byte(sharingkey))
	newHmac.Write(wholeData)
	newHmacBlock := newHmac.Sum(nil)

	//Append first new block at last block's position i.e. oldHMAC
	remainingLength := len(newEncryptedData)
	start := 0
	end := configBlockSize
	id := inode[len(inode)-1]
	userlib.DatastoreSet(id.String(), newEncryptedData[start:end])
	start += configBlockSize
	end += configBlockSize
	remainingLength -= configBlockSize

	for len(inode)*16 < configBlockSize {
		if remainingLength == 0 {
			macUUID := uuid.New()
			inode = append(inode, macUUID)
			userlib.DatastoreSet(macUUID.String(), newHmacBlock)
			encodedInode, _ := json.Marshal(inode)
			userlib.DatastoreSet(inodeID.String(), encodedInode)
			break
		}
		id := uuid.New()
		inode = append(inode, id)
		userlib.DatastoreSet(id.String(), newEncryptedData[start:end])
		start += configBlockSize
		end += configBlockSize
		remainingLength -= configBlockSize
	}

	for remainingLength > 0 {
		inode := []uuid.UUID{}
		inodeUUID := uuid.New()
		inodeIndirect = append(inodeIndirect, inodeUUID)

		for len(inode)*16 < configBlockSize {
			if remainingLength == 0 {
				break
			}
			id := uuid.New()
			inode = append(inode, id)
			userlib.DatastoreSet(id.String(), newEncryptedData[start:end])
			start += configBlockSize
			end += configBlockSize
			remainingLength -= configBlockSize
		}

		if remainingLength == 0 {
			macUUID := uuid.New()
			inode = append(inode, macUUID)
			userlib.DatastoreSet(macUUID.String(), newHmacBlock)
			encodedInode, _ := json.Marshal(inode)
			userlib.DatastoreSet(inodeUUID.String(), encodedInode)
			break
		}

		encodedInode, _ := json.Marshal(inode)
		userlib.DatastoreSet(inodeUUID.String(), encodedInode)
	}

	encodedIndirectnode, _ := json.Marshal(inodeIndirect)
	userlib.DatastoreSet(string(hashkey), encodedIndirectnode)

	return
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	fileUUID := userdata.FileKey[filename]
	var record sharingRecord
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)
	sharingdata, _ := userlib.DatastoreGet(sharingkey[:8])
	if err := json.Unmarshal(sharingdata, &record); err != nil {
		panic(err)
	}
	hmac := userlib.NewHMAC(sharingdata)
	hashkey := hmac.Sum(nil)

	inodeIndirect := []uuid.UUID{}
	encodedIndirectInode, _ := userlib.DatastoreGet(string(hashkey))
	if err := json.Unmarshal(encodedIndirectInode, &inodeIndirect); err != nil {
		panic(err)
	}

	encryptedData := []byte{} //For retrieval of encrypted data
	iv := []byte{}
	hmacBlock := []byte{}
	firstInode := true

	indirectInodeOffset := 0 //(offset + 1) / (configBlockSize / 16)
	inodeOffset := 1         //(offset + 1) % (configBlockSize / 16)

	for i := indirectInodeOffset; i < len(inodeIndirect); i++ {
		id := inodeIndirect[i].String()
		inode := []uuid.UUID{}
		encodedInode, _ := userlib.DatastoreGet(id)
		if err := json.Unmarshal(encodedInode, &inode); err != nil {
			panic(err)
		}
		j := 0
		if i == indirectInodeOffset {
			j = inodeOffset
		}
		for ; j < len(inode); j++ {
			if firstInode { //Get iv from first id
				iv, _ = userlib.DatastoreGet(inode[0].String())
				firstInode = false
			}

			dataBlockID := inode[j].String()

			if i == len(inodeIndirect)-1 && j == len(inode)-1 { //get HMAC from last id
				hmacBlock, _ = userlib.DatastoreGet(dataBlockID)
				break
			}
			dataBlock, _ := userlib.DatastoreGet(dataBlockID)
			encryptedData = append(encryptedData, dataBlock...)
		}
	}
	mac := userlib.NewHMAC([]byte(sharingkey))
	mac.Write(encryptedData)
	h := mac.Sum(nil)
	if hex.EncodeToString(h) != hex.EncodeToString(hmacBlock) {
		err := errors.New("HMAC verification failed : Data Corrupted")
		return nil, err
	}

	decryptedData := make([]byte, len(encryptedData))
	aesCypherStream := userlib.CFBDecrypter([]byte(sharingkey), iv)
	aesCypherStream.XORKeyStream(decryptedData, encryptedData)

	return decryptedData[offset*configBlockSize:], nil
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	fileUUID := userdata.FileKey[filename]
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)
	sharingdata, _ := userlib.DatastoreGet(sharingkey[:8])
	hmac := userlib.NewHMAC(sharingdata)
	hashkey := hmac.Sum(nil)
	var record sharingRecord
	if err := json.Unmarshal(sharingdata, &record); err != nil {
		panic(err)
	}
	record.UserNames = append(record.UserNames, recipient)
	sharingdataNEW, err := json.Marshal(record)

	//Saving sharingDataNew
	userlib.DatastoreSet(sharingkey[:8], sharingdataNEW)

	hmacNEW := userlib.NewHMAC(sharingdataNEW)
	hashkeyNEW := hmacNEW.Sum(nil)
	encodedIndirectInode, _ := userlib.DatastoreGet(string(hashkey))
	userlib.DatastoreSet(string(hashkeyNEW), encodedIndirectInode)
	data := make([]byte, configBlockSize)
	userlib.DatastoreSet(string(hashkey), data)
	m := userdata.FileKey[filename]
	mSIGN, _ := userlib.RSASign(userdata.Key, []byte(m.String()))

	pubkey, _ := userlib.KeystoreGet(recipient)
	mINBYTE := []byte(m.String())
	byteMsg, _ := userlib.RSAEncrypt(&pubkey, mINBYTE, []byte("share"))
	byteMsg = append(byteMsg, mSIGN...)
	msgid = string(byteMsg)
	return
}

// ReceiveFile : Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	byteMsg := []byte(msgid)
	sig := byteMsg[36:]
	mINBYTE, _ := userlib.RSADecrypt(userdata.Key, byteMsg[:36], []byte("share"))
	pubkey, _ := userlib.KeystoreGet(sender)
	userlib.RSAVerify(&pubkey, byteMsg[:36], sig)
	m, _ := uuid.ParseBytes(mINBYTE[:36])
	userdata.FileKey[filename] = m

	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	FileID    uuid.UUID
	UserNames []string
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	var user User
	//Storing values in User
	user.Username = username
	user.Password = password
	user.Key, err = userlib.GenerateRSAKey()
	user.FileKey = make(map[string]uuid.UUID)
	if err != nil {
		panic(err)
	}

	//Setting public key in Keystore
	userlib.KeystoreSet(user.Username, user.Key.PublicKey)

	storageKey := userlib.Argon2Key([]byte(password), []byte(username), 32)
	encryptionKey := userlib.Argon2Key([]byte(password), []byte(""), 32)
	iv := make([]byte, aes.BlockSize)
	iv = userlib.RandomBytes(aes.BlockSize)
	ivUUID := uuid.New()
	userlib.DatastoreSet(ivUUID.String(), iv) //Store iv into Datastore
	inode := []uuid.UUID{ivUUID}              //Save ivUUID to inode
	aesCypherStream := userlib.CFBEncrypter(encryptionKey, iv)

	//Encrypting and storing user
	data, err := json.Marshal(user)
	encryptedData := make([]byte, len(data))
	aesCypherStream.XORKeyStream(encryptedData, data) //Encrypt user
	mac := userlib.NewHMAC(encryptionKey)             //Create HMAC
	mac.Write(encryptedData)

	if len(encryptedData) <= configBlockSize {
		id := uuid.New()
		inode = append(inode, id)
		userlib.DatastoreSet(id.String(), encryptedData)
	} else {
		start := 0
		end := configBlockSize
		remainingLength := len(encryptedData)
		for {
			if remainingLength == 0 {
				break
			}
			if remainingLength < configBlockSize {
				id := uuid.New()
				inode = append(inode, id)
				userlib.DatastoreSet(id.String(), encryptedData[start:])
				break
			}
			id := uuid.New()
			inode = append(inode, id)
			userlib.DatastoreSet(id.String(), encryptedData[start:end])
			start += configBlockSize
			end += configBlockSize
			remainingLength -= configBlockSize
		}
	}
	//Append HMAC
	macUUID := uuid.New()
	hmacBlock := mac.Sum(nil)
	inode = append(inode, macUUID)
	userlib.DatastoreSet(macUUID.String(), hmacBlock)

	encodedInode, _ := json.Marshal(inode)
	userlib.DatastoreSet(string(storageKey), encodedInode)

	return &user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	var user User
	storageKey := userlib.Argon2Key([]byte(password), []byte(username), 32)
	decryptionKey := userlib.Argon2Key([]byte(password), []byte(""), 32)
	encodedInode, ok := userlib.DatastoreGet(string(storageKey))
	if !ok {
		err := errors.New("Invalid Username or Password")
		return nil, err
	}

	inode := []uuid.UUID{}
	if err := json.Unmarshal(encodedInode, &inode); err != nil {
		panic(err)
	}

	data := []byte{} //For retrieval of encrypted data
	iv := []byte{}
	hmacBlock := []byte{}
	for i, v := range inode {
		if i == 0 { //Retrieve iv
			iv, ok = userlib.DatastoreGet(v.String())
			if !ok {
				err := errors.New("Data Corrupted")
				return nil, err
			}
		} else if i == len(inode)-1 { //Retrieve hmac
			hmacBlock, ok = userlib.DatastoreGet(v.String())
		} else {
			block, ok := userlib.DatastoreGet(v.String())
			if !ok {
				err := errors.New("Data Corrupted")
				return nil, err
			}
			data = append(data, block...)
		}
	}

	mac := userlib.NewHMAC(decryptionKey)
	mac.Write(data)

	if hex.EncodeToString(mac.Sum(nil)) != hex.EncodeToString(hmacBlock) {
		err := errors.New("HMAC verification failed : Data Corrupted")
		return nil, err
	}

	encodedUser := make([]byte, len(data))
	aesCypherStream := userlib.CFBDecrypter(decryptionKey, iv)
	aesCypherStream.XORKeyStream(encodedUser, data)

	if err := json.Unmarshal(encodedUser, &user); err != nil {
		panic(err)
	}

	return &user, nil
}

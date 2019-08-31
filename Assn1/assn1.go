package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

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
	Key      *userlib.PrivateKey
	FileKey  map[string]uuid.UUID
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	//check userdata
	_, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {

		return err
	}

	//create file id and store it to userdata
	fileUUID := uuid.New()
	userdata.FileKey[filename] = fileUUID

	//create and popullate instance of sharing record
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)

	//check data length
	if (len(data) % configBlockSize) != 0 {
		err := errors.New("Invalid Data Size")
		return err
	}

	//create inodeindirect and add one inode
	//and save it to location pointed by
	//first 8 bytes of sharing key
	inodeIndirect := []uuid.UUID{}
	inodeID := uuid.New()
	inode := []uuid.UUID{}
	inodeIndirect = append(inodeIndirect, inodeID)

	//save encoded inode
	encodedInode, _ := json.Marshal(inode)
	userlib.DatastoreSet(inodeID.String(), encodedInode)

	//save encoded inodeindirect
	encodedInodeIndirect, _ := json.Marshal(inodeIndirect)
	userlib.DatastoreSet(string(sharingkey[:8]), encodedInodeIndirect)

	//save data to empty file
	err = userdata.AppendFile(filename, data)
	return
}

// AppendFile :should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//check userdata
	_, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {

		return err
	}

	//Get old encrypted data
	fileUUID := userdata.FileKey[filename]
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)

	inodeIndirect := []uuid.UUID{}
	encodedIndirectInode, ok := userlib.DatastoreGet(string(sharingkey[:8]))
	if !ok {
		z := errors.New("unable to get data from datastore")
		return z
	}
	if err := json.Unmarshal(encodedIndirectInode, &inodeIndirect); err != nil {
		return err
	}

	inodeID := inodeIndirect[len(inodeIndirect)-1]
	inode := []uuid.UUID{}
	encodedInode, ok := userlib.DatastoreGet(inodeID.String())
	if !ok {
		err := errors.New("unable to get data from datastore")
		return err
	}
	if err := json.Unmarshal(encodedInode, &inode); err != nil {
		return err
	}

	start := 0
	end := configBlockSize
	remainingLength := len(data)
	for len(inode)*16 <= configBlockSize {
		if len(inode)*16 == configBlockSize {
			encodedInode, _ := json.Marshal(inode)
			userlib.DatastoreSet(inodeID.String(), encodedInode)
			break
		}
		if remainingLength == 0 {
			//save inode
			encodedInode, _ := json.Marshal(inode)
			userlib.DatastoreSet(inodeID.String(), encodedInode)

			//save indirect inode
			encodedIndirectInode, _ := json.Marshal(inodeIndirect)
			userlib.DatastoreSet(string(sharingkey[:8]), encodedIndirectInode)
			break
		}
		id := uuid.New()
		inode = append(inode, id)
		block := data[start:end]
		start += configBlockSize
		end += configBlockSize
		remainingLength -= configBlockSize

		//calculate iv
		blockIV := userlib.RandomBytes(userlib.BlockSize)

		//encrypt data using iv
		aesCypherStream := userlib.CFBEncrypter([]byte(sharingkey), blockIV)
		encryptedBlock := make([]byte, len(block))
		aesCypherStream.XORKeyStream(encryptedBlock, block)

		//storageblock = iv+encrypted data
		storageBlock := append(blockIV, encryptedBlock...)

		//Calculate HMAC
		mac := userlib.NewHMAC([]byte(sharingkey))
		mac.Write(storageBlock)
		blockHmac := mac.Sum(nil)
		storageBlock = append(storageBlock, blockHmac...)

		//Store iv+data+hmac as a block on datastore
		userlib.DatastoreSet(id.String(), storageBlock)
	}
	for remainingLength > 0 {
		//create inode and add its id to inodeindirect
		inode := []uuid.UUID{}
		inodeID := uuid.New()
		inodeIndirect = append(inodeIndirect, inodeID)

		for len(inode)*16 <= configBlockSize {
			if len(inode)*16 == configBlockSize {
				encodedInode, _ := json.Marshal(inode)
				userlib.DatastoreSet(inodeID.String(), encodedInode)
				break
			}
			if remainingLength == 0 {
				//save inode
				encodedInode, _ := json.Marshal(inode)
				userlib.DatastoreSet(inodeID.String(), encodedInode)

				//save indirect inode
				encodedIndirectInode, _ := json.Marshal(inodeIndirect)
				userlib.DatastoreSet(string(sharingkey[:8]), encodedIndirectInode)
				break
			}
			id := uuid.New()
			inode = append(inode, id)
			block := data[start:end]
			start += configBlockSize
			end += configBlockSize
			remainingLength -= configBlockSize

			//calculate iv
			blockIV := userlib.RandomBytes(userlib.BlockSize)

			//encrypt data using iv
			aesCypherStream := userlib.CFBEncrypter([]byte(sharingkey), blockIV)
			encryptedBlock := make([]byte, len(block))
			aesCypherStream.XORKeyStream(encryptedBlock, block)

			//storageblock = iv+encrypted data
			storageBlock := append(blockIV, encryptedBlock...)

			//Calculate HMAC
			mac := userlib.NewHMAC([]byte(sharingkey))
			mac.Write(storageBlock)
			blockHmac := mac.Sum(nil)
			storageBlock = append(storageBlock, blockHmac...)

			//Store iv+data+hmac as a block on datastore
			userlib.DatastoreSet(id.String(), storageBlock)
		}
	}
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
	//check userdata
	_, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}

	//retrieve filepointer and sharing data
	fileUUID := userdata.FileKey[filename]
	sharingkey := strings.Replace(fileUUID.String(), "-", "", -1)

	//retrieve indirectInode Block from sharingkey
	inodeIndirect := []uuid.UUID{}
	encodedIndirectInode, ok := userlib.DatastoreGet(string(sharingkey[:8]))
	if !ok {
		z := errors.New("unable to get data from datastore")
		return nil, z
	}
	if err := json.Unmarshal(encodedIndirectInode, &inodeIndirect); err != nil {
		return nil, err
	}

	//calculate inode block where Datablock ID is present
	blockPerInode := configBlockSize / 16
	inodeIndirectOffset := offset / blockPerInode
	inodeOffset := offset % blockPerInode
	inodeID := inodeIndirect[inodeIndirectOffset]
	encodedInode, ok := userlib.DatastoreGet(inodeID.String())
	if !ok {
		z := errors.New("unable to get data from datastore")
		return nil, z
	}
	inode := []uuid.UUID{}
	if err := json.Unmarshal(encodedInode, &inode); err != nil {
		return []byte(" "), err
	}
	dataBlockID := inode[inodeOffset]

	//Retrieve Datablock
	totalData, ok := userlib.DatastoreGet(dataBlockID.String())
	if !ok {
		z := errors.New("unable to get data from datastore")
		return nil, z
	}

	//Extract hmac from datablock
	hmacData := totalData[(configBlockSize + 16):]
	encryptedData := totalData[:(configBlockSize + 16)] //encrypted data + iv

	//Calculate hash of encrypted data + iv
	mac := userlib.NewHMAC([]byte(sharingkey))
	mac.Write(encryptedData)
	h := mac.Sum(nil)
	//Compare hash
	if hex.EncodeToString(h) != hex.EncodeToString(hmacData) {
		err := errors.New("HMAC verification failed : Data Corrupted")
		return nil, err
	}
	iv := encryptedData[:16]
	//encryptedData =  // only encrypted data of size=configBlockSize
	decryptedData := make([]byte, len(encryptedData[16:]))
	aesCypherStream := userlib.CFBDecrypter([]byte(sharingkey), iv)
	aesCypherStream.XORKeyStream(decryptedData, encryptedData[16:])

	return decryptedData, nil

}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	//check userdata
	_, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return "", err
	}

	fileUUID := userdata.FileKey[filename]

	mSIGN, err := userlib.RSASign(userdata.Key, []byte(fileUUID.String()))
	if err != nil {
		return "", err
	}

	pubkey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		z := errors.New("unable to get data from keystore")
		return "", z
	}
	mINBYTE := []byte(fileUUID.String())
	byteMsg, err := userlib.RSAEncrypt(&pubkey, mINBYTE, []byte(""))
	if err != nil {
		return "", err
	}
	byteMsg = append(byteMsg, mSIGN...)
	msgid = string(byteMsg)
	return msgid, nil
}

// ReceiveFile : Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	//check userdata
	_, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	byteMsg := []byte(msgid)
	sign := byteMsg[256:]
	mINBYTE, err := userlib.RSADecrypt(userdata.Key, byteMsg[:256], []byte(""))
	if err != nil {
		return err
	}
	pubkey, ok := userlib.KeystoreGet(sender)
	if !ok {
		z := errors.New("unable to get data from keystore")
		return z
	}
	if err := userlib.RSAVerify(&pubkey, mINBYTE, sign); err != nil {
		return err
	}

	m, err := uuid.ParseBytes(mINBYTE)
	if err != nil {
		return err
	}
	userdata.FileKey[filename] = m

	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	//check userdata
	_, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	//Get sharingRecord
	oldFileID := userdata.FileKey[filename]
	oldSharingkey := strings.Replace(oldFileID.String(), "-", "", -1)
	encodedIndirectInode, ok := userlib.DatastoreGet(oldSharingkey[:8])
	if !ok {
		z := errors.New("unable to get data from datastore")
		return z
	}
	indirectInode := []uuid.UUID{}
	if err := json.Unmarshal(encodedIndirectInode, &indirectInode); err != nil {
		return err
	}

	data := []byte{} //get total decrypted data into this variable
	offset := 0
	for _, inodeID := range indirectInode {
		inode := []uuid.UUID{}
		encodedInode, ok := userlib.DatastoreGet(inodeID.String())
		if !ok {
			z := errors.New("data not found")
			return z
		}
		if err := json.Unmarshal(encodedInode, &inode); err != nil {
			return err
		}
		for range inode {
			block, err := userdata.LoadFile(filename, offset)
			if err != nil {
				return err
			}
			data = append(data, block...)
			offset++
		}
	}
	userlib.DatastoreSet(oldSharingkey[:8], []byte(""))
	userdata.StoreFile(filename, data)
	return nil
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
	FileID    string
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
	//check single user multiple instances
	u, _ := GetUser(username, password)
	if u != nil {
		z := errors.New("User already present")
		return nil, z
	}

	var user User
	//Storing values in User
	user.Username = username
	user.Password = password
	user.Key, err = userlib.GenerateRSAKey()
	user.FileKey = make(map[string]uuid.UUID)
	if err != nil {
		return nil, err
	}

	//Setting public key in Keystore
	userlib.KeystoreSet(user.Username, user.Key.PublicKey)

	storageKey := userlib.Argon2Key([]byte(password), []byte(username), 32)
	encryptionKey := userlib.Argon2Key([]byte(password), []byte(""), 32)

	//calculate iv
	blockIV := userlib.RandomBytes(userlib.BlockSize)

	//marshal user
	block, err := json.Marshal(user)

	//encrypt data using iv
	aesCypherStream := userlib.CFBEncrypter([]byte(encryptionKey), blockIV)
	encryptedBlock := make([]byte, len(block))
	aesCypherStream.XORKeyStream(encryptedBlock, block)

	//storageblock = iv+encrypted data
	storageBlock := append(blockIV, encryptedBlock...)

	//Calculate HMAC
	mac := userlib.NewHMAC([]byte(encryptionKey))
	mac.Write(storageBlock)
	blockHmac := mac.Sum(nil)
	storageBlock = append(storageBlock, blockHmac...)

	//Store iv+data+hmac as a block on datastore
	userlib.DatastoreSet(string(storageKey), storageBlock)

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
	data, ok := userlib.DatastoreGet(string(storageKey))
	if !ok {
		err := errors.New("Invalid Username or Password")
		return nil, err
	}

	mac := userlib.NewHMAC(decryptionKey)
	mac.Write(data[:len(data)-32])

	if hex.EncodeToString(mac.Sum(nil)) != hex.EncodeToString(data[len(data)-32:]) {
		err := errors.New("HMAC verification failed : Data Corrupted")
		return nil, err
	}

	iv := data[:userlib.BlockSize]
	encodedUser := make([]byte, len(data)-userlib.BlockSize-32)
	aesCypherStream := userlib.CFBDecrypter(decryptionKey, iv)
	aesCypherStream.XORKeyStream(encodedUser, data[userlib.BlockSize:len(data)-32])

	if err := json.Unmarshal(encodedUser, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

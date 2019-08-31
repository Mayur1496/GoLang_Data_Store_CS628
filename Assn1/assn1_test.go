package assn1

import (
	"reflect"
	"testing"

	"github.com/sarkarbidya/CS628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	_, err1 := InitUser("amiya", "abcd")
	_, e := GetUser("amiya", "abcd")
	if e != nil {
		t.Error(e)
	}
	//t.Log(userlib.DatastoreGetMap())
	if err1 != nil {
		t.Log("Failed to initialize user")

	} else {
		t.Error("Initialized invalid user", err1)
	}

	// add more test cases here
}

func TestGetUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	_, err1 := GetUser("amiya", "abcd")
	if err1 != nil {
		t.Log("Failed to initialize user")

	} else {
		t.Error("Initialized invalid user", err1)
	}
	// add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	u1, _ := InitUser("amiya", "abcd")
	v := userlib.DatastoreGetMap()
	t.Log(v)
	data1 := make([]byte, 4096*150)
	e := u1.StoreFile("file1", data1)
	if e != nil {
		panic(e)
	}
	data2, _ := u1.LoadFile("file1", 0)

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}

	e = u1.AppendFile("file1", data1)
	if e != nil {
		panic(e)
	}

	data3, _ := u1.LoadFile("file1", 270)
	t.Log(len(data3))

	// add test cases here
}

func TestUserStorage(t *testing.T) {
	u1, err1 := GetUser("amiya", "abcd")
	if err1 != nil {
		t.Log("Cannot load data for invalid user", u1)
	} else {
		t.Error("Data loaded for invalid user", u1)
	}
	// add more test cases here
}

func TestFileShareReceive(t *testing.T) {
	u1, _ := InitUser("amiya", "abcd")
	v := userlib.DatastoreGetMap()
	t.Log(v)
	data1 := make([]byte, 4096*300)
	e := u1.StoreFile("file1", data1)
	if e != nil {
		panic(e)
	}

	u2, e := InitUser("suraj", "efgh")
	msg, e := u1.ShareFile("file1", "suraj")
	e = u2.ReceiveFile("file2", "amiya", msg)
	if e != nil {
		panic(e)
	}
	recievedData, e := u2.LoadFile("file2", 0)
	if e != nil {
		panic(e)
	}
	t.Log(recievedData)

	u1.RevokeFile("file1")
	recievedData2, e := u2.LoadFile("file2", 0)
	if e != nil {
		panic(e)
	}
	t.Log(recievedData2)

	// add test cases here
}

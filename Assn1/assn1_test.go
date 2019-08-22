package assn1

import "github.com/sarkarbidya/CS628-assn1/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	_, err1 := InitUser("", "")
	if err1 != nil {
		t.Log("Failed to initialize user")
		
	}else{
		t.Error("Initialized invalid user", err1)
	}

	// add more test cases here 
}
	


func TestUserStorage(t *testing.T) { 
	u1, err1 := GetUser("", "fubar")
	if err1 != nil {
		t.Log("Cannot load data for invalid user",u1)
	}else{
		t.Error("Data loaded for invalid user", err1)
	}

	// add more test cases here
}



func TestFileStoreLoadAppend(t *testing.T) {
	data1 := userlib.RandomBytes(4096)
	_ := u1.StoreFile("file1", data1)

	data2, _ := u1.LoadFile("file1",0) 
	

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	}else{
		t.Log("data is not corrupted")
	}

	// add test cases here
}


func TestFileShareReceive(t *testing.T) {
	// add test cases here
}

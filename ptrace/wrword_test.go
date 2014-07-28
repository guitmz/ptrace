package ptrace
import "bytes"
import "encoding/binary"
import "testing"

// this is the entry point of programs for linux/amd64.
// we don't care so much about it, per se; we just need an address which we can
// guarantee is valid, so that any errors reading/writing to it must be bugs in
// our code (as opposed to just an invalid address)
const entry = 0x00400000

// this is just a word that is ridiculously unlikely to actually be in the
// binary.
const cc = uint64(0xCCccCCccCCccCCcc)

func TestWritingWord(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
	}
	_, err = tracee.ReadWord(entry)
	if err != nil {
		t.Fatalf("could not read first word of program image: %v\n", err)
	}
	err = tracee.WriteWord(entry, cc)
	if err != nil { t.Fatalf("%v\n", err) }
}

func TestWritingArray(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
	}
	// ugh.	0x00400000 is specific to linux/amd64.
	_, err = tracee.ReadWord(0x00400000)
	if err != nil {
		t.Fatalf("could not read first word of program image: %v\n", err)
	}
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, cc)
	if err != nil { t.Fatalf("filling buf: %v\n", err) }

	err = tracee.Write(0x00400000, buf.Bytes())
	if err != nil { t.Fatalf("%v\n", err) }

	// now make sure we get the same thing back when we read it.
	var word uint64
	if word, err = tracee.ReadWord(0x00400000) ; err != nil {
		t.Fatalf("could not read entry point word: %v\n", err)
	}
	if word != cc {
		t.Fatalf("write of 0x%x silently failed: left 0x%x\n", cc, word)
	}
	tracee.Close()
}

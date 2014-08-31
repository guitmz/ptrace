package ptrace
import "testing"

func TestSyscall(t *testing.T) {
	inferior, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
		t.FailNow()
	}
	<- inferior.Events()
	if err := inferior.Syscall() ; err != nil {
		t.Fatalf("could not syscall-step: %v", err)
	}
}

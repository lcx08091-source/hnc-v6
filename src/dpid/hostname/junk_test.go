package hostname

import "testing"

func TestIsJunk(t *testing.T) {
	for _, s := range []string{"null", "NULL", " Null ", "(null)", "nil", "none", "(none)",
		"undefined", "unknown", "UNKNOWN", "localhost", "localhost.localdomain",
		"*", "-", "", "   ", "\t", "0", "12345"} {
		if !IsJunk(s) {
			t.Errorf("IsJunk(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"Mi-10", "nullify", "iPhone", "localhost2", "123abc", "a",
		"Johns-MacBook", "客厅电视", "-x", "none-pc"} {
		if IsJunk(s) {
			t.Errorf("IsJunk(%q) = true, want false", s)
		}
	}
}

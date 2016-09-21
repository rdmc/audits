package mac

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var parseMACTests = []struct {
	in  string
	out MAC
	err string
}{
	{"0123.4567.89ab", MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, ""},
	{"0123456789ab", MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, ""},
	{"01:23:45:67:89:ab", MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, ""},
	{"01-23-45-67-89-ab", MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, ""},
	{"ab:cd:ef:AB:CD:EF", MAC{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef}, ""},
	{"0000111122223333", nil, "invalid MAC address"},
	{"abcd.efAB.aDEF.0123", nil, "EUI-64 not suported"},
	{"01:23:45:67:89:ab:cd:ef", nil, "EUI-64 not suported"},
	{"00:11:22:33:44-55", nil, "invalid MAC address"},
	{"00.11.22.33.44.55", nil, "invalid MAC address"},
	{"00-11-22-33-44:55", nil, "invalid MAC address"},
}

func TestParseMAC(t *testing.T) {

	match := func(err error, s string) bool {
		if s == "" {
			return err == nil
		}
		return err != nil && strings.Contains(err.Error(), s)
	}

	for i, tt := range parseMACTests {
		out, err := ParseMAC(tt.in)
		if !reflect.DeepEqual(out, tt.out) || !match(err, tt.err) {
			t.Errorf("ParseMAC(%q) = %v, %v, want %v, %v", tt.in, out, err, tt.out, tt.err)
		}
		if tt.err == "" {
			// Verify that serialization works too, and that in roud-trips.
			s := out.String()
			out2, err := ParseMAC(s)
			if err != nil {
				t.Errorf("%d. ParseMAC(%q) = %v", i, s, err)
				continue
			}
			if !reflect.DeepEqual(out2, out) {
				t.Errorf("%d. ParseMAC(%q) = %v, want %v", i, s, out2, out)
			}
		}
	}
}

// quik and dirty ....
func getFunctionName(i interface{}) string {
	fn := runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
	// return only the name, excludes type, package, file, etc...
	return fn[strings.LastIndex(fn, ".")+1:]
}

var stringMACTest = []struct {
	in  MAC
	out string
	fn  func(MAC) string
}{
	{MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, "0123456789ab", MAC.PlainString},
	{MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, "01:23:45:67:89:ab", MAC.String},
	{MAC{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, "0123.4567.89ab", MAC.CiscoString},
}

func TestStringMAC(t *testing.T) {
	for i, tt := range stringMACTest {
		s := tt.fn(tt.in)
		if s != tt.out {
			t.Errorf("%d. %v(%v) = %q, want %q", i, getFunctionName(tt.fn), tt.in, s, tt.out)
		}
	}
}

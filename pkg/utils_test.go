package pkg

import (
	"testing"
)

func TestArrayDiff(t *testing.T) {
	var arrayDiffEntries = []struct {
		old, new, add, del []string
	}{
		{[]string{"a"}, []string{}, []string{}, []string{"a"}},
		{[]string{"a", "b"}, []string{"a"}, []string{}, []string{"b"}},
	}

	for i, entry := range arrayDiffEntries {
		add, del := ArrayDiff(entry.old, entry.new)
		if !ArrayEqual(add, entry.add) || !ArrayEqual(del, entry.del) {
			t.Errorf("%d: ArrayDiff(%v, %v) want: %v, %v, got: %v, %v",
				i, entry.old, entry.new, entry.add, entry.del, add, del,
			)
		}
	}
}

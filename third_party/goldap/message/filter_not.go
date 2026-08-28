package message

import "fmt"

func (filterNot FilterNot) getFilterTag() int {
	return TagFilterNot
}

// not             [2] Filter,
func (filterNot FilterNot) size() (size int) {
	size = filterNot.Filter.size()
	size += sizeTagAndLength(tagSequence, size)
	return
}

func (filterNot *FilterNot) readComponents(bytes *Bytes) (err error) {
	filterNot.Filter, err = readFilter(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}

// not             [2] Filter,
func (filterNot FilterNot) write(bytes *Bytes) (size int) {
	size = filterNot.Filter.write(bytes)
	size += bytes.WriteTagAndLength(classContextSpecific, isCompound, TagFilterNot, size)
	return
}

// not             [2] Filter,
func readFilterNot(bytes *Bytes) (filternot FilterNot, err error) {
	// See readFilterAnd's identical guard (filter_and.go) and
	// maxFilterNestingDepth (filter.go).
	if bytes.filterDepth >= maxFilterNestingDepth {
		err = LdapError{fmt.Sprintf("readFilterNot: filter nesting exceeds maximum depth %d", maxFilterNestingDepth)}
		return
	}
	err = bytes.ReadSubBytes(classContextSpecific, TagFilterNot, func(sub *Bytes) error {
		sub.filterDepth = bytes.filterDepth + 1
		return filternot.readComponents(sub)
	})
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterNot:\n%s", err.Error())}
		return
	}
	return
}

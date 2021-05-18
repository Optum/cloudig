package aws

// Contains tells whether slice of strings 'ss' contains string 's'.
func Contains(ss []string, s string) bool {
	for _, n := range ss {
		if s == n {
			return true
		}
	}
	return false
}


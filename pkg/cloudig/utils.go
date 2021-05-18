package cloudig

// Contains tells whether slice of strings 'ss' contains string 's'.
func Contains(ss []string, s string) bool {
	for _, n := range ss {
		if s == n {
			return true
		}
	}
	return false
}

// find the min of a & b
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ContainsKey returns value if key present in slice of map[string]string
func ContainsKey(sm []map[string]string, key string) string {
	for _, sm := range sm {
		for k, v := range sm {
			if k == key {
				return v
			}
		}
	}
	return "NEW_FINDING"
}

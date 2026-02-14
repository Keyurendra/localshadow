package container

// resetNamespaceCache clears cached namespace lookups at scan start so
// runtime changes between runs don't leak stale state into new scans.
func (s *s) resetNamespaceCache() {
	s.mu.Lock()
	s.nsCache = make(map[string][]string)
	s.mu.Unlock()
}

// cachedNamespaces returns previously discovered namespaces per socket,
// minimizing control-plane RPC overhead during a single scan run.
func (s *s) cachedNamespaces(host string) ([]string, bool) {
	s.mu.RLock()
	ns, ok := s.nsCache[host]
	s.mu.RUnlock()
	return ns, ok
}

// cacheNamespaces stores discovery results by runtime socket so all
// image attempts share the same namespace view during the run.
func (s *s) cacheNamespaces(host string, namespaces []string) {
	s.mu.Lock()
	s.nsCache[host] = namespaces
	s.mu.Unlock()
}

// utilities/id_lookup.go
package utilities

import (
	"os/user"
	"strconv"
	"sync"
)

// userCache maps UID -> username
// groupCache maps GID -> groupname
var (
	userCache       = make(map[uint32]string)
	groupCache      = make(map[uint32]string)
	userCacheMutex  sync.RWMutex
	groupCacheMutex sync.RWMutex
)

// LookupUserName returns the username for the given uid.
// It checks the cache first; on a miss it calls os/user.LookupId,
// stores the result in the cache, and returns it.
func LookupUserName(uid uint32) string {
	// Fast path: read-lock
	userCacheMutex.RLock()
	if name, ok := userCache[uid]; ok {
		userCacheMutex.RUnlock()
		return name
	}
	userCacheMutex.RUnlock()

	// Cache miss: look up in OS
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	name := strconv.Itoa(int(uid))
	if err == nil && u.Username != "" {
		name = u.Username
	}

	// Store in cache
	userCacheMutex.Lock()
	userCache[uid] = name
	userCacheMutex.Unlock()

	return name
}

// LookupGroupName returns the groupname for the given gid.
// It checks the cache first; on a miss it calls os/user.LookupGroupId,
// stores the result in the cache, and returns it.
func LookupGroupName(gid uint32) string {
	// Fast path: read-lock
	groupCacheMutex.RLock()
	if name, ok := groupCache[gid]; ok {
		groupCacheMutex.RUnlock()
		return name
	}
	groupCacheMutex.RUnlock()

	// Cache miss: look up in OS
	g, err := user.LookupGroupId(strconv.Itoa(int(gid)))
	name := strconv.Itoa(int(gid))
	if err == nil && g.Name != "" {
		name = g.Name
	}

	// Store in cache
	groupCacheMutex.Lock()
	groupCache[gid] = name
	groupCacheMutex.Unlock()

	return name
}

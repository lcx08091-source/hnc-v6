// Package output - entity.go (v5.7.0-rc3)
//
// Curated entity library: a license-clean, HNC-authored map of apex(eTLD+1) →
// {type, entity} for well-known SHARED infrastructure (CDN, cloud/object
// storage, analytics, ads, push SDKs, ...). It is NOT a third-party tracker
// dataset (Tracker Radar et al. are CC-BY-NC-SA / GPL and can't be bundled in
// a redistributed module).
//
// Purpose in the candidate flywheel (走法2): a cold-start prior for the
// "shared vs app-specific" decision. uid-cardinality is the durable signal,
// but it needs several windows to accumulate; the entity DB lets dpid know
// "akamaiedge.net is a CDN" on the FIRST sighting, so a CDN/analytics apex is
// never auto-attributed to whichever uid happened to hit it first.
//
// File: /data/local/hnc/etc/entity_db.json (soft-installed + version-upgraded
// from the module's data/entity_db.json by service.sh). Re-read each tick like
// the blocklist; missing/malformed = empty (best-effort, never fatal).

package output

import (
	"encoding/json"
	"os"
	"strings"
)

const entityDBFile = "/data/local/hnc/etc/entity_db.json"

type entityRec struct {
	Type   string `json:"type"`
	Entity string `json:"entity,omitempty"`
}

type entityDBData struct {
	Version  string               `json:"version,omitempty"`
	Comment  string               `json:"_comment,omitempty"`
	Entities map[string]entityRec `json:"entities"`
}

// entitySharedTypes are the entity types that mark an apex as shared
// infrastructure → never attributed to a single app by the flywheel.
var entitySharedTypes = map[string]struct{}{
	"cdn": {}, "cloud": {}, "hosting": {}, "analytics": {}, "ads": {},
	"advertising": {}, "push": {}, "social": {}, "tracker": {}, "sdk": {},
	"shared": {}, "infra": {},
}

// loadEntityDB reads the curated entity library. Keys lowercased; missing or
// malformed file yields an empty map (feature simply no-ops).
func loadEntityDB() map[string]entityRec {
	out := map[string]entityRec{}
	data, err := os.ReadFile(entityDBFile)
	if err != nil {
		return out
	}
	var db entityDBData
	if err := json.Unmarshal(data, &db); err != nil {
		return out
	}
	for apex, rec := range db.Entities {
		out[strings.ToLower(strings.TrimSpace(apex))] = rec
	}
	return out
}

// entityIsShared reports whether the entity DB classifies apex as shared
// infrastructure (so it must not be attributed to a single app).
func entityIsShared(apex string, db map[string]entityRec) bool {
	rec, ok := db[apex]
	if !ok {
		return false
	}
	_, shared := entitySharedTypes[strings.ToLower(strings.TrimSpace(rec.Type))]
	return shared
}

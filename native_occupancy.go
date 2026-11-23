package main

import (
	"encoding/json"
	"errors"
)

func validateNativeOccupancy(p *nativePayload, total int64) error {
	if !nativeIDPattern.MatchString(p.RequestID) || !nativeIDPattern.MatchString(p.Lease.ID) || int64(p.Version) > 9007199254740991 {
		return errors.New("invalid native occupancy request identity")
	}
	for _, source := range p.SourceDocuments {
		if int64(source.Version) > 9007199254740991 || (source.Kind == "assembly" && source.ConfigurationID != nil) {
			return errors.New("invalid native occupancy source identity")
		}
	}
	return validateNativeAssembly(p, total)
}

// Occupancy uses v2's geometry closure, but separately admits its v4 action.
func unmarshalNativeOccupancy(data []byte, p *nativePayload) error {
	var wire map[string]any
	if json.Unmarshal(data, &wire) != nil || !nativeExactFields(wire, []string{"contractVersion", "targetKind", "requestId", "documentId", "version", "snapshotId", "document", "configurationId", "operation", "limits", "assemblyLimits", "sourceDocuments", "assets", "closureHash", "lease", "runtime"}) || !nativeSummaryCount(wire["version"], 9007199254740991) {
		return errors.New("invalid native occupancy assignment fields")
	}
	sources, ok := wire["sourceDocuments"].([]any)
	if !ok {
		return errors.New("invalid native occupancy source list")
	}
	for _, raw := range sources {
		source, ok := raw.(map[string]any)
		if !ok || !nativeExactFields(source, []string{"kind", "id", "version", "snapshotId", "configurationId", "document"}) || !nativeSummaryCount(source["version"], 9007199254740991) {
			return errors.New("invalid native occupancy source fields")
		}
		document, ok := source["document"].(map[string]any)
		if !ok || !nativeExactFields(document, []string{"hash", "size", "url"}) {
			return errors.New("invalid native occupancy source file")
		}
	}
	return decodeNativeAssignment(data, wire, p)
}

func validateNativeOccupancyFile(file map[string]any) error {
	if !nativeExactFields(file, []string{"format", "hash", "size"}) || file["format"] != "json" || !nativeSummaryCount(file["size"], 8<<20) || file["size"].(float64) <= 0 {
		return errors.New("invalid native occupancy output file")
	}
	hash, ok := file["hash"].(string)
	if !ok || !nativeHashPattern.MatchString(hash) {
		return errors.New("invalid native occupancy output digest")
	}
	return nil
}

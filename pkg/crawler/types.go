package crawler

import "github.com/aquasecurity/trivy-java-db/pkg/types"

type Metadata struct {
	GroupID    string     `xml:"groupId"`
	ArtifactID string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
}

type Versioning struct {
	Latest      string   `xml:"latest"`
	Release     string   `xml:"release"`
	Versions    []string `xml:"versions>version"`
	LastUpdated string   `xml:"lastUpdated"`
}

type Index struct {
	URL          string
	LocalPath    string
	GroupID      string
	ArtifactID   string
	Version      string
	Versions     []Version
	ArchiveType  types.ArchiveType
	ExpectedPURL string
}
type Version struct {
	Version string
	SHA1    []byte
}

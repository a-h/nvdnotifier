package nvd

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Meta contains information about the last update to the NVD.
type Meta struct {
	LastModifiedDate time.Time `json:"lastModifiedDate"`
	Size             int64     `json:"size"`
	ZipSize          int64     `json:"zipSize"`
	GZSize           int64     `json:"gzSize"`
	SHA256           string    `json:"sha256"`
}

// Example file:
// lastModifiedDate:2018-11-17T14:01:52-05:00
// size:13869565
// zipSize:601309
// gzSize:601165
// sha256:A19EC051954B8B6EB49BB7CB911A2B194D729D409EBC2F9DD21B93E8B0418803

// RecentMetadata returns metadata about the current version of the "recent" file.
func RecentMetadata() (m Meta, err error) {
	return getMetadata("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.meta")
}

// ModifiedMetadata returns metadata about the current version of the "modified" file.
func ModifiedMetadata() (m Meta, err error) {
	return getMetadata("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.meta")
}

func getMetadata(url string) (m Meta, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		firstColon := strings.Index(line, ":")
		if firstColon == -1 {
			continue
		}
		prefix := string([]rune(line)[:firstColon])
		suffix := string([]rune(line)[firstColon+1:])
		switch prefix {
		case "lastModifiedDate":
			if m.LastModifiedDate, err = time.Parse(time.RFC3339, suffix); err != nil {
				err = fmt.Errorf("could not parse '%v' as time: %v", suffix, err)
				return
			}
		case "size":
			if m.Size, err = strconv.ParseInt(suffix, 10, 64); err != nil {
				err = fmt.Errorf("could not parse size '%v' as int64: %v", suffix, err)
				return
			}
		case "zipSize":
			if m.ZipSize, err = strconv.ParseInt(suffix, 10, 64); err != nil {
				err = fmt.Errorf("could not parse zipSize '%v' as int64: %v", suffix, err)
				return
			}
		case "gzSize":
			if m.GZSize, err = strconv.ParseInt(suffix, 10, 64); err != nil {
				err = fmt.Errorf("could not parse gzSize '%v' as int64: %v", suffix, err)
				return
			}
		case "sha256":
			m.SHA256 = suffix
		}
	}
	if sErr := scanner.Err(); sErr != nil {
		err = sErr
		return
	}
	return
}

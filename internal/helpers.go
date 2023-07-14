package pkg

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func HeuristicNormalisePath(path string) (string, error) {
	path = strings.Trim(path, `\`)

	splitted := strings.SplitN(path, `\`, 2)
	if len(splitted) != 2 {
		return "", fmt.Errorf("cannot determine path %v", path)
	}

	var normalisedPath string

	switch prefix := strings.ToLower(splitted[0]); prefix {
	case "system32":
		kf, err := windows.KnownFolderPath(windows.FOLDERID_System, windows.KF_FLAG_NO_ALIAS)
		if err != nil {
			return "", fmt.Errorf("cannot determine known folder %v: %v", prefix, err)
		}
		normalisedPath = filepath.Join(kf, splitted[1])
	case "systemroot":
		kf, err := windows.KnownFolderPath(windows.FOLDERID_Windows, windows.KF_FLAG_NO_ALIAS)
		if err != nil {
			return "", fmt.Errorf("cannot determine known folder %v: %v", prefix, err)
		}
		normalisedPath = filepath.Join(kf, splitted[1])
	case "??":
		normalisedPath = splitted[1]
	}

	if _, err := os.Stat(normalisedPath); err != nil {
		return "", fmt.Errorf("normalised path %v does not exist: %v", normalisedPath, err)
	}

	return normalisedPath, nil
}

func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func PrintLolDrivers(drivers []LolDriver) {
	maxFilenameLen := 0
	maxPathLen := 0
	maxStatusLen := 0
	maxCVEsLen := 0
	maxIDLen := 0
	maxSha256Len := 0

	for _, driver := range drivers {
		if len(driver.Filename) > maxFilenameLen {
			maxFilenameLen = len(driver.Filename)
		}
		if len(driver.Path) > maxPathLen {
			maxPathLen = len(driver.Path)
		}
		if len(driver.Status) > maxStatusLen {
			maxStatusLen = len(driver.Status)
		}
		cves := strings.Join(driver.CVEs, ", ")
		if len(cves) > maxCVEsLen {
			maxCVEsLen = len(cves)
		}
		if len(driver.ID) > maxIDLen {
			maxIDLen = len(driver.ID)
		}
		if len(driver.Sha256) > maxSha256Len {
			maxSha256Len = len(driver.Sha256)
		}
	}

	fmt.Printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
		maxFilenameLen, "Filename",
		maxPathLen, "Path",
		maxStatusLen, "Status",
		maxIDLen, "ID",
		maxSha256Len, "Sha256",
		maxCVEsLen, "CVEs",
	)
	fmt.Printf("%s  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", maxFilenameLen),
		strings.Repeat("-", maxPathLen),
		strings.Repeat("-", maxStatusLen),
		strings.Repeat("-", maxIDLen),
		strings.Repeat("-", maxSha256Len),
		strings.Repeat("-", maxCVEsLen),
	)

	for _, driver := range drivers {
		cves := strings.Join(driver.CVEs, ", ")
		fmt.Printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
			maxFilenameLen, driver.Filename,
			maxPathLen, driver.Path,
			maxStatusLen, driver.Status,
			maxIDLen, driver.ID,
			maxSha256Len, driver.Sha256,
			maxCVEsLen, cves,
		)
	}
}

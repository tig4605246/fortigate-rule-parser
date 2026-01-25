package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"static-traffic-analyzer/internal/engine"
	"static-traffic-analyzer/internal/model"
	"static-traffic-analyzer/internal/parser"
	"static-traffic-analyzer/internal/utils"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
)

var (
	srcFile      string
	dstFile      string
	portsFile    string
	rulesFile    string
	rulesDB      string
	outFile      string
	routableFile string
	workers      int
	logLevel     string
	logFile      string
	ruleProvider string
	matchMode    string
	maxHosts     uint64
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "static-traffic-analyzer",
		Short: "A high-performance static firewall rule analyzer",
		Long: `static-traffic-analyzer reads firewall policies and simulates traffic
	flows to determine whether they are allowed or denied based on the rule set.`,
		RunE: run,
	}

	// Set up flags
	rootCmd.Flags().StringVar(&srcFile, "src", "", "Source IP list CSV file (required)")
	rootCmd.Flags().StringVar(&dstFile, "dst", "", "Destination IP list CSV file (required)")
	rootCmd.Flags().StringVar(&portsFile, "ports", "", "Ports list file (required)")
	rootCmd.Flags().StringVar(&ruleProvider, "provider", "fortigate", "Rule provider type: 'fortigate' or 'mariadb'")
	rootCmd.Flags().StringVar(&rulesFile, "rules", "", "Firewall configuration file (for 'fortigate' provider)")
	rootCmd.Flags().StringVar(&rulesDB, "db", "", "Database connection string (for 'mariadb' provider)")
	rootCmd.Flags().StringVar(&outFile, "out", "results.csv", "Output CSV file for all results")
	rootCmd.Flags().StringVar(&routableFile, "routable", "routable.csv", "Output CSV file for accepted traffic")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "Number of concurrent workers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	rootCmd.Flags().StringVar(&logFile, "log-file", "", "Log file path (default: stderr)")

	// Matching mode flags
	rootCmd.Flags().StringVar(&matchMode, "mode", "sample", "Matching mode: 'sample' (test first IP) or 'expand' (test all IPs in small CIDRs)")
	rootCmd.Flags().Uint64Var(&maxHosts, "max-hosts", 65536, "Maximum number of hosts in a CIDR to expand in 'expand' mode")

	// Mark required flags
	rootCmd.MarkFlagRequired("src")
	rootCmd.MarkFlagRequired("dst")
	rootCmd.MarkFlagRequired("ports")

	return rootCmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// --- 1. Setup Logging ---
	logger := setupLogger(logLevel, logFile)
	slog.SetDefault(logger)

	slog.Info("Starting Static Traffic Analyzer", "version", "1.0-go")
	startTime := time.Now()

	// --- 2. Load Policies ---
	slog.Info("Loading policies...", "provider", ruleProvider)
	policies, err := loadPolicies(ruleProvider, rulesFile, rulesDB)
	if err != nil {
		slog.Error("Failed to load policies", "error", err)
		return err
	}
	slog.Info("Successfully loaded policies", "count", len(policies))

	// --- 3. Create Evaluator ---
	evaluator := engine.NewEvaluator(policies)

	// --- 4. Open Input Files ---
	srcF, err := os.Open(srcFile)
	if err != nil {
		slog.Error("Failed to open source IP file", "path", srcFile, "error", err)
		return err
	}
	defer srcF.Close()

	dstF, err := os.Open(dstFile)
	if err != nil {
		slog.Error("Failed to open destination IP file", "path", dstFile, "error", err)
		return err
	}
	defer dstF.Close()

	portsF, err := os.Open(portsFile)
	if err != nil {
		slog.Error("Failed to open ports file", "path", portsFile, "error", err)
		return err
	}
	defer portsF.Close()

	// --- 5. Parse Input Traffic Definitions ---
	slog.Info("Parsing input traffic files")
	traffic, err := parser.ParseInputTraffic(srcF, dstF, portsF)
	if err != nil {
		slog.Error("Failed to parse input traffic", "error", err)
		return err
	}
	slog.Info("Input traffic parsed", "source_cidrs", len(traffic.SrcIPs), "destination_cidrs", len(traffic.DstIPs), "ports", len(traffic.Ports))

	totalTasks := estimateTotalTasks(traffic, matchMode, maxHosts)
	slog.Info("Task count estimated", "total_tasks", totalTasks)

	var completedTasks uint64
	progressDone := make(chan struct{})
	if totalTasks > 0 {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					done := atomic.LoadUint64(&completedTasks)
					remaining := uint64(0)
					if done < totalTasks {
						remaining = totalTasks - done
					}
					slog.Info("Progress", "total_tasks", totalTasks, "remaining_tasks", remaining)
					if done >= totalTasks {
						return
					}
				case <-progressDone:
					return
				}
			}
		}()
	}

	// --- 6. Setup Worker Pool and Channels ---
	tasks := make(chan model.Task, workers*100)
	results := make(chan model.SimulationResult, workers*100)
	var wg sync.WaitGroup

	// --- 7. Start Writer Goroutine ---
	slog.Info("Starting result writer", "output_file", outFile, "routable_file", routableFile)
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go resultWriter(&writerWg, results, outFile, routableFile, &completedTasks)

	// --- 8. Start Worker Goroutines ---
	slog.Info("Starting evaluator workers", "count", workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(&wg, i+1, evaluator, tasks, results)
	}

	// --- 9. Start Producer Goroutine ---
	go func() {
		slog.Info("Starting task producer", "mode", matchMode)
		taskCount := 0
		for _, srcNet := range traffic.SrcIPs {
			for _, dst := range traffic.DstIPs {
				for _, portInfo := range traffic.Ports {

					srcHosts := []net.IP{srcNet.IP}
					dstHosts := []net.IP{dst.IPNet.IP}

					if matchMode == "expand" {
						srcSize := utils.CIDRSize(srcNet)
						if srcSize > 1 && srcSize <= maxHosts {
							slog.Debug("Expanding source CIDR", "cidr", srcNet.String(), "size", srcSize)
							srcHosts = expandCIDR(srcNet)
						}
						dstSize := utils.CIDRSize(dst.IPNet)
						if dstSize > 1 && dstSize <= maxHosts {
							slog.Debug("Expanding destination CIDR", "cidr", dst.IPNet.String(), "size", dstSize)
							dstHosts = expandCIDR(dst.IPNet)
						}
					}

					for _, srcIP := range srcHosts {
						for _, dstIP := range dstHosts {
							tasks <- model.Task{
								SrcIP:        srcIP,
								SrcCIDR:      srcNet.String(),
								DstIP:        dstIP,
								DstCIDR:      dst.IPNet.String(),
								DstMeta:      dst.Metadata,
								Port:         portInfo.Port,
								Proto:        portInfo.Protocol,
								ServiceLabel: portInfo.Label,
							}
							taskCount++
						}
					}
				}
			}
		}
		close(tasks) // Close tasks channel when producer is done
		slog.Info("Task producer finished", "total_tasks", taskCount)
	}()

	// --- 10. Wait for Workers and Writer ---
	wg.Wait()       // Wait for all workers to finish
	close(results)  // Close results channel to signal writer
	writerWg.Wait() // Wait for writer to finish writing all buffered results
	close(progressDone)

	slog.Info("Analysis complete", "duration", time.Since(startTime))
	return nil
}

// ...

// expandCIDR iterates through all IPs in a CIDR.
func expandCIDR(cidr *net.IPNet) []net.IP {
	var ips []net.IP
	// Get the first IP of the CIDR
	ip := cidr.IP.Mask(cidr.Mask)
	for ; cidr.Contains(ip); utils.Inc(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}
	return ips
}

func estimateTotalTasks(traffic *parser.InputTraffic, mode string, maxHosts uint64) uint64 {
	if traffic == nil {
		return 0
	}

	var total uint64
	for _, srcNet := range traffic.SrcIPs {
		srcCount := uint64(1)
		if mode == "expand" {
			size := utils.CIDRSize(srcNet)
			if size > 1 && size <= maxHosts {
				srcCount = size
			}
		}

		for _, dst := range traffic.DstIPs {
			dstCount := uint64(1)
			if mode == "expand" {
				size := utils.CIDRSize(dst.IPNet)
				if size > 1 && size <= maxHosts {
					dstCount = size
				}
			}

			for range traffic.Ports {
				total += srcCount * dstCount
			}
		}
	}

	return total
}

func setupLogger(level, logFilePath string) *slog.Logger {
	var logWriter io.Writer = os.Stderr
	if logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logWriter = f
		}
		// We don't log an error here because the logger isn't set up yet.
		// It will just fall back to stderr.
	}

	var lvl slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "INFO":
		lvl = slog.LevelInfo
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: lvl}))
}

func loadPolicies(provider, rulesPath, dbConnStr string) ([]model.Policy, error) {
	switch provider {
	case "fortigate":
		if rulesPath == "" {
			return nil, fmt.Errorf("rules file path must be provided for fortigate provider")
		}
		file, err := os.Open(rulesPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		p := parser.NewFortiGateParser(file)
		if err := p.Parse(); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return p.Policies, nil
	case "mariadb":
		if dbConnStr == "" {
			return nil, fmt.Errorf("database connection string must be provided for mariadb provider")
		}
		p, err := parser.NewMariaDBParser(dbConnStr)
		if err != nil {
			return nil, err
		}
		defer p.Close()
		if err := p.Parse(); err != nil {
			return nil, err
		}
		return p.Policies, nil
	default:
		return nil, fmt.Errorf("unknown rule provider: %s", provider)
	}
}

func worker(wg *sync.WaitGroup, id int, evaluator *engine.Evaluator, tasks <-chan model.Task, results chan<- model.SimulationResult) {
	defer wg.Done()
	slog.Debug("Worker started", "id", id)
	for task := range tasks {
		result := evaluator.Evaluate(&task)
		// Populate metadata for the output
		result.SrcNetworkSegment = task.SrcCIDR
		result.DstNetworkSegment = task.DstCIDR
		result.ServiceLabel = task.ServiceLabel
		result.Port = task.Port
		result.Protocol = string(task.Proto)
		if val, ok := task.DstMeta["dst_gn"]; ok {
			result.DstGn = val
		}
		if val, ok := task.DstMeta["dst_site"]; ok {
			result.DstSite = val
		}
		if val, ok := task.DstMeta["dst_location"]; ok {
			result.DstLocation = val
		}

		results <- result
	}
	slog.Debug("Worker finished", "id", id)
}

func resultWriter(wg *sync.WaitGroup, results <-chan model.SimulationResult, outPath, routablePath string, completedTasks *uint64) {
	defer wg.Done()

	outFile, err := os.Create(outPath)
	if err != nil {
		slog.Error("Failed to create output file", "path", outPath, "error", err)
		return
	}
	defer outFile.Close()

	routableFile, err := os.Create(routablePath)
	if err != nil {
		slog.Error("Failed to create routable file", "path", routablePath, "error", err)
		return
	}
	defer routableFile.Close()

	outWriter := csv.NewWriter(outFile)
	defer outWriter.Flush()
	routableWriter := csv.NewWriter(routableFile)
	defer routableWriter.Flush()

	// Write headers
	header := []string{"src_network_segment", "dst_network_segment", "dst_gn", "dst_site", "dst_location", "service_label", "protocol", "port", "decision", "matched_policy_id", "matched_policy_action", "reason"}
	outWriter.Write(header)
	routableWriter.Write(header)

	var written uint64
	for result := range results {
		record := []string{
			result.SrcNetworkSegment,
			result.DstNetworkSegment,
			result.DstGn,
			result.DstSite,
			result.DstLocation,
			result.ServiceLabel,
			result.Protocol,
			fmt.Sprintf("%d", result.Port),
			result.Decision,
			result.MatchedPolicyID,
			result.MatchedPolicyAction,
			result.Reason,
		}
		outWriter.Write(record)
		if result.Decision == "ALLOW" {
			routableWriter.Write(record)
		}
		written++
		if written%1024 == 0 {
			atomic.StoreUint64(completedTasks, written)
		}
	}
	atomic.StoreUint64(completedTasks, written)
	slog.Info("Result writer finished")
}

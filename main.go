package main

import (
        "time"
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "os"
        "os/exec"
        "strings"
)

type Package struct {
        Name    string `json:"name"`
        Version string `json:"version"`
}

type CISCheck struct {
        CheckName string `json:"check_name"`
        Status    string `json:"status"`
        Evidence  string `json:"evidence"`
}

func getInstalledPackages() ([]Package, error) {
        cmd := exec.Command("dpkg", "-l")
        output, err := cmd.Output()
        if err != nil {
                return nil, err
        }

        lines := strings.Split(string(output), "\n")
        var packages []Package

        for _, line := range lines {
                fields := strings.Fields(line)
                if len(fields) > 4 && fields[0] == "ii" {
                        pkg := Package{
                                Name:    fields[1],
                                Version: fields[2],
                        }
                        packages = append(packages, pkg)
                }
        }

        return packages, nil
}

func checkRootLogin() CISCheck {
        data, err := os.ReadFile("/etc/ssh/sshd_config")
        if err != nil {
                return CISCheck{
                        CheckName: "Root Login Disabled Over SSH",
                        Status:    "ERROR",
                        Evidence:  err.Error(),
                }
        }

        content := string(data)

        if strings.Contains(content, "PermitRootLogin no") {
                return CISCheck{
                        CheckName: "Root Login Disabled Over SSH",
                        Status:    "PASS",
                        Evidence:  "PermitRootLogin no found",
                }
        }

        return CISCheck{
                CheckName: "Root Login Disabled Over SSH",
                Status:    "FAIL",
                Evidence:  "PermitRootLogin no not explicitly set",
        }
}

func checkFirewall() CISCheck {
        cmd := exec.Command("ufw", "status")
        output, err := cmd.Output()
        if err != nil {
                return CISCheck{
                        CheckName: "Firewall Enabled (UFW)",
                        Status:    "ERROR",
                        Evidence:  err.Error(),
                }
        }

        content := string(output)

        if strings.Contains(content, "Status: active") {
                return CISCheck{
                        CheckName: "Firewall Enabled (UFW)",
                        Status:    "PASS",
                        Evidence:  "UFW is active",
                }
        }

        return CISCheck{
                CheckName: "Firewall Enabled (UFW)",
                Status:    "FAIL",
                Evidence:  content,
        }
}
func checkAuditd() CISCheck {
        cmd := exec.Command("systemctl", "is-active", "auditd")
        output, _ := cmd.CombinedOutput()

        status := strings.TrimSpace(string(output))

        if status == "active" {
                return CISCheck{
                        CheckName: "Auditd Service Running",
                        Status:    "PASS",
                        Evidence:  "auditd service is active",
                }
        }

        if status == "inactive" || status == "failed" {
                return CISCheck{
                        CheckName: "Auditd Service Running",
                        Status:    "FAIL",
                        Evidence:  "auditd service is not active",
                }
        }

        return CISCheck{
                CheckName: "Auditd Service Running",
                Status:    "ERROR",
                Evidence:  status,
        }
}
func checkAppArmor() CISCheck {
        cmd := exec.Command("aa-status")
        output, err := cmd.Output()
        if err != nil {
                return CISCheck{
                        CheckName: "AppArmor Enabled",
                        Status:    "ERROR",
                        Evidence:  err.Error(),
                }
        }

        content := string(output)

        if strings.Contains(content, "profiles are loaded") &&
                strings.Contains(content, "profiles are in enforce mode") {
                return CISCheck{
                        CheckName: "AppArmor Enabled",
                        Status:    "PASS",
                        Evidence:  "AppArmor profiles are loaded and enforced",
                }
        }

        return CISCheck{
                CheckName: "AppArmor Enabled",
                Status:    "FAIL",
                Evidence:  "AppArmor not properly enforced",
        }
}
func checkPasswordExpiration() CISCheck {
        data, err := os.ReadFile("/etc/login.defs")
        if err != nil {
                return CISCheck{
                        CheckName: "Password Expiration Policy Enforced",
                        Status:    "ERROR",
                        Evidence:  err.Error(),
                }
        }

        lines := strings.Split(string(data), "\n")

        for _, line := range lines {
                if strings.HasPrefix(strings.TrimSpace(line), "PASS_MAX_DAYS") {
                        fields := strings.Fields(line)
                        if len(fields) >= 2 {
                                value := fields[1]

                                if value != "99999" {
                                        return CISCheck{
                                                CheckName: "Password Expiration Policy Enforced",
                                                Status:    "PASS",
                                                Evidence:  "PASS_MAX_DAYS set to " + value,
                                        }
                                }

                                return CISCheck{
                                        CheckName: "Password Expiration Policy Enforced",
                                        Status:    "FAIL",
                                        Evidence:  "PASS_MAX_DAYS set to 99999 (no expiration)",
                                }
                        }
                }
        }

        return CISCheck{
                CheckName: "Password Expiration Policy Enforced",
                Status:    "FAIL",
                Evidence:  "PASS_MAX_DAYS not configured",
        }
}
func checkPasswordComplexity() CISCheck {
        data, err := os.ReadFile("/etc/pam.d/common-password")
        if err != nil {
                return CISCheck{
                        CheckName: "Password Complexity Enforced",
                        Status:    "ERROR",
                        Evidence:  err.Error(),
                }
        }

        content := string(data)

        if strings.Contains(content, "pam_pwquality.so") {
                return CISCheck{
                        CheckName: "Password Complexity Enforced",
                        Status:    "PASS",
                        Evidence:  "pam_pwquality module configured",
                }
        }

        return CISCheck{
                CheckName: "Password Complexity Enforced",
                Status:    "FAIL",
                Evidence:  "pam_pwquality module not found",
        }
}
func checkUnusedFilesystems() CISCheck {
        filesystems := []string{"cramfs", "squashfs"}

        for _, fs := range filesystems {
                cmd := exec.Command("modprobe", "-n", "-v", fs)
                out, _ := cmd.CombinedOutput()
                output := strings.TrimSpace(string(out))

                if output==""{
                        continue
                }

                if strings.Contains(output, "/bin/true") {
                        continue
                }

                return CISCheck{
                        CheckName: "Unused Filesystems Disabled",
                        Status:    "FAIL",
                        Evidence:  fs + " module is loadable",
                }
        }

        return CISCheck{
                CheckName: "Unused Filesystems Disabled",
                Status:    "PASS",
                Evidence:  "cramfs and squashfs are disabled or not present",
        }
}
func checkTimeSync() CISCheck {
        cmd := exec.Command("systemctl", "is-active", "chrony")
        output, _ := cmd.CombinedOutput()

        status := strings.TrimSpace(string(output))

        if status == "active" {
                return CISCheck{
                        CheckName: "Time Synchronization (chrony)",
                        Status:    "PASS",
                        Evidence:  "chrony service is active",
                }
        }

        return CISCheck{
                CheckName: "Time Synchronization (chrony)",
                Status:    "FAIL",
                Evidence:  "chrony service is not active",
        }
}

func checkWorldWritableFiles() CISCheck {
        cmd := exec.Command("bash", "-c", "find / -xdev -type f -perm -0002 2>/dev/null")
        output, _ := cmd.CombinedOutput()

        if len(strings.TrimSpace(string(output))) == 0 {
                return CISCheck{
                        CheckName: "No World-Writable Files",
                        Status:    "PASS",
                        Evidence:  "No world-writable files found",
                }
        }

        return CISCheck{
                CheckName: "No World-Writable Files",
                Status:    "FAIL",
                Evidence:  "World-writable files exist",
        }
}
func checkGDM() CISCheck {
        cmd := exec.Command("bash", "-c", "dpkg -l | grep gdm")
        output, _ := cmd.CombinedOutput()

        if len(strings.TrimSpace(string(output))) == 0 {
                return CISCheck{
                        CheckName: "GDM Auto-Login Disabled",
                        Status:    "PASS",
                        Evidence:  "GDM not installed",
                }
        }

        return CISCheck{
                CheckName: "GDM Auto-Login Disabled",
                Status:    "FAIL",
                Evidence:  "GDM installed - verify auto-login manually",
        }
}
func sendToCloud(jsonData []byte) error {
    url := "https://gaaugzfa06.execute-api.ap-south-1.amazonaws.com/prod/ingest"

    resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    fmt.Println("Cloud response status:", resp.Status)
    return nil
}

func runAgent() {
    fmt.Println("Starting CIS scan...")

    packages, _ := getInstalledPackages()

    cisResults := []CISCheck{
        checkRootLogin(),
        checkFirewall(),
        checkAuditd(),
        checkAppArmor(),
        checkPasswordExpiration(),
        checkPasswordComplexity(),
        checkUnusedFilesystems(),
        checkTimeSync(),
        checkWorldWritableFiles(),
        checkGDM(),
    }

    total := len(cisResults)
    passed := 0
    failed := 0

    for _, check := range cisResults {
        if check.Status == "PASS" {
            passed++
        } else if check.Status == "FAIL" {
            failed++
        }
    }

    summary := map[string]interface{}{
        "total_checks":  total,
        "passed":        passed,
        "failed":        failed,
        "score_percent": (passed * 100) / total,
    }

    host, _ := os.Hostname()

    output := map[string]interface{}{
        "hostname":    host,
        "packages":    packages,
        "cis_results": cisResults,
        "summary":     summary,
    }

    jsonData, _ := json.MarshalIndent(output, "", "  ")

    err := sendToCloud(jsonData)
    if err != nil {
        fmt.Println("Error sending data:", err)
    } else {
        fmt.Println("Scan completed and data sent successfully.")
    }
}

func main() {
    fmt.Println("CIS Agent started...")

    for {
        runAgent()
        fmt.Println("Sleeping for 15 minutes...")
        time.Sleep(15 * time.Minute)
    }
}



package ssh

// diagnostics_test.go — allowlist hygiene, adversarial parameter validation,
// and tier gating for the remote diagnostics table.

import (
	"strings"
	"testing"
)

// TestDiagTable_Hygiene enforces the structural invariants every allowlist
// row must satisfy: unique names, a valid tier, at least one OS variant, no
// shell metacharacters outside the single validated %s slot, and no
// credential-reading commands.
func TestDiagTable_Hygiene(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range diagTable {
		if d.Name == "" {
			t.Fatal("diagnostic with empty name")
		}
		if seen[d.Name] {
			t.Errorf("%s: duplicate name", d.Name)
		}
		seen[d.Name] = true
		if d.Tier != TierReadonly && d.Tier != TierFull {
			t.Errorf("%s: invalid tier %q (off may never be a requirement)", d.Name, d.Tier)
		}
		if d.Linux == "" && d.Windows == "" {
			t.Errorf("%s: no OS variant", d.Name)
		}
		if d.Describe == "" {
			t.Errorf("%s: missing description", d.Name)
		}
		for osName, tmpl := range map[string]string{"linux": d.Linux, "windows": d.Windows} {
			if tmpl == "" {
				continue
			}
			slots := strings.Count(tmpl, "%s")
			if d.Param && slots != 1 {
				t.Errorf("%s (%s): parameterized spec must have exactly one %%s slot, has %d", d.Name, osName, slots)
			}
			if !d.Param && slots != 0 {
				t.Errorf("%s (%s): fixed spec must have no %%s slot", d.Name, osName)
			}
			if d.Param && !strings.Contains(tmpl, "'%s'") {
				t.Errorf("%s (%s): the %%s slot must be single-quoted", d.Name, osName)
			}
			// No command may read credential/private-key material.
			for _, banned := range []string{"id_rsa", "shadow", "passwd ", ".pem", "PrivateKey", "token", "Get-Credential"} {
				if strings.Contains(strings.ToLower(tmpl), strings.ToLower(banned)) {
					t.Errorf("%s (%s): command references credential material %q", d.Name, osName, banned)
				}
			}
		}
	}
}

func TestDiagCommand_ParamValidation(t *testing.T) {
	// Accepted realistic unit/service names.
	for _, ok := range []string{"nginx.service", "w3svc", "postgres@14", "Micro-soft.Windows_Update:1"} {
		if _, _, err := DiagCommand("svc-status", "linux", TierReadonly, ok); err != nil {
			t.Errorf("param %q should be accepted: %v", ok, err)
		}
	}
	// Adversarial values must be REFUSED (never sanitized).
	for _, bad := range []string{
		"; rm -rf /", "a'b", `a"b`, "a b", "a|b", "a$(id)", "a`id`", "a\nb", "-flag",
		strings.Repeat("x", 200), "",
	} {
		if _, _, err := DiagCommand("svc-status", "linux", TierReadonly, bad); err == nil {
			t.Errorf("param %q must be refused", bad)
		}
	}
	// Fixed commands refuse any parameter.
	if _, _, err := DiagCommand("sys-disk", "linux", TierReadonly, "sneaky"); err == nil {
		t.Error("fixed command must refuse parameters")
	}
	// The substituted command carries the value only inside single quotes.
	cmd, _, err := DiagCommand("svc-status", "linux", TierReadonly, "nginx.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "'nginx.service'") {
		t.Errorf("substituted command: %q", cmd)
	}
}

func TestDiagCommand_TierGating(t *testing.T) {
	// readonly cannot obtain full-tier commands.
	if _, _, err := DiagCommand("auth-log", "linux", TierReadonly, ""); err == nil {
		t.Error("auth-log must require the full tier")
	}
	if _, _, err := DiagCommand("auth-log", "linux", TierFull, ""); err != nil {
		t.Errorf("full tier should allow auth-log: %v", err)
	}
	// off obtains nothing.
	if _, _, err := DiagCommand("sys-disk", "linux", TierOff, ""); err == nil {
		t.Error("tier off must refuse every diagnostic")
	}
	// Unknown name / missing OS variant.
	if _, _, err := DiagCommand("nonexistent", "linux", TierFull, ""); err == nil {
		t.Error("unknown diagnostic must be refused")
	}
	if _, _, err := DiagCommand("iis-apppools", "linux", TierFull, ""); err == nil {
		t.Error("iis-apppools has no linux variant and must be refused there")
	}
	if _, _, err := DiagCommand("cert-expiry", "linux", TierFull, ""); err == nil {
		t.Error("cert-expiry has no linux variant and must be refused there")
	}
}

func TestParseDiagTier(t *testing.T) {
	cases := map[string]DiagTier{"": TierReadonly, "readonly": TierReadonly, "off": TierOff, "FULL": TierFull}
	for in, want := range cases {
		got, err := ParseDiagTier(in)
		if err != nil || got != want {
			t.Errorf("ParseDiagTier(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseDiagTier("yolo"); err == nil {
		t.Error("invalid tier must error")
	}
}

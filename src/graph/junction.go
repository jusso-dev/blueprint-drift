package graph

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// CommandRunner executes a local CLI command and returns its stdout bytes.
type CommandRunner func(ctx context.Context, binary string, args ...string) ([]byte, error)

// JunctionClient is an optional read-only Microsoft Graph backend backed by
// jusso-dev/junction (https://github.com/jusso-dev/junction).
type JunctionClient struct {
	Binary     string
	Context    string
	Operations map[string]string // maps "/v1.0/..." or "/beta/..." to junction operation ID
	Runner     CommandRunner
}

var blockedJunctionVerbs = []string{
	".create",
	".update",
	".delete",
	".patch",
	".post",
	".put",
	".remove",
	".revoke",
	".assign",
	".reset",
	".invoke",
}

// NewJunctionClient creates an optional read-only Junction backend adapter.
func NewJunctionClient(binary, junctionContext string, operations map[string]string) *JunctionClient {
	if binary == "" {
		binary = "junction"
	}
	return &JunctionClient{
		Binary:     binary,
		Context:    junctionContext,
		Operations: operations,
		Runner:     defaultCommandRunner,
	}
}

// Get executes a mapped read-only Graph operation through the local junction binary.
func (j *JunctionClient) Get(ctx context.Context, version, endpoint string) (*Response, error) {
	return j.execute(ctx, version, endpoint, false)
}

// GetAllPages executes a mapped read-only Graph operation through junction with --all paging.
func (j *JunctionClient) GetAllPages(ctx context.Context, version, endpoint string) (*Response, error) {
	return j.execute(ctx, version, endpoint, true)
}

func (j *JunctionClient) execute(ctx context.Context, version, endpoint string, allPages bool) (*Response, error) {
	if version != "v1.0" && version != "beta" {
		return nil, fmt.Errorf("unsupported Graph version %q", version)
	}
	key := fmt.Sprintf("/%s%s", version, endpoint)
	op, ok := j.Operations[key]
	if !ok || strings.TrimSpace(op) == "" {
		return nil, fmt.Errorf("no junction operation mapped for %s", key)
	}
	if err := validateReadOnlyJunctionOp(op); err != nil {
		return nil, err
	}

	args := make([]string, 0, 10)
	if j.Context != "" {
		args = append(args, "--context", j.Context)
	}
	args = append(args, "execute", op, "--input", "{}", "--json")
	if allPages {
		args = append(args, "--all")
	}

	runner := j.Runner
	if runner == nil {
		runner = defaultCommandRunner
	}
	out, err := runner(ctx, j.Binary, args...)
	if err != nil {
		return nil, fmt.Errorf("junction execute %s: %w", op, err)
	}
	canonical := CanonicalJSON(out)
	return &Response{
		Query:      fmt.Sprintf("GET /%s%s (junction:%s)", version, endpoint, op),
		StatusCode: 200,
		RawBody:    canonical,
		SHA256:     DigestSHA256(canonical),
		Pages:      1,
	}, nil
}

func validateReadOnlyJunctionOp(op string) error {
	lower := strings.ToLower(strings.TrimSpace(op))
	if lower == "" {
		return errors.New("empty junction operation")
	}
	for _, verb := range blockedJunctionVerbs {
		if strings.HasSuffix(lower, verb) || strings.Contains(lower, verb+".") {
			return fmt.Errorf("%w: junction operation %q is not read-only", ErrWriteMethodBlocked, op)
		}
	}
	return nil
}

func defaultCommandRunner(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

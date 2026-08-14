package certproto

import "encoding/json"

// CapabilitiesURLs 是 v2 公共端点的相对 URL 模板。
// 模板中的花括号变量必须由调用方按路径段规则转义后替换。
type CapabilitiesURLs struct {
	// Capabilities 是能力发现端点。
	Capabilities string `json:"capabilities"`
	// Jobs 是任务查询端点。
	Jobs string `json:"jobs"`
	// Reconcile 是证书 reconcile 端点。
	Reconcile string `json:"reconcile"`
	// Status 是证书状态端点。
	Status string `json:"status"`
	// Manifest 是 generation manifest 端点。
	Manifest string `json:"manifest"`
	// Files 是 generation 文件端点。
	Files string `json:"files"`
	// Deployments 是部署回报端点。
	Deployments string `json:"deployments"`
}

// CapabilityURLs 是 CapabilitiesURLs 的兼容性别名。
type CapabilityURLs = CapabilitiesURLs

// Validate 校验所有能力 URL 都是当前 v2 冻结的端点模板。
func (u CapabilitiesURLs) Validate() error {
	expected := DefaultCapabilitiesURLs()
	if u != expected {
		return protocolError(ErrorCodeInvalidCapabilities, "capabilities 中的 URL 必须匹配 v2 端点模板")
	}
	return nil
}

// Capabilities 描述服务端支持的 v2 公共协议语义和端点。
type Capabilities struct {
	// APIVersion 是公共协议主版本。
	APIVersion string `json:"api_version"`
	// AsyncJobs 表示 reconcile 使用异步任务模型。
	AsyncJobs bool `json:"async_jobs"`
	// JobPolling 表示可以通过 jobs URL 轮询任务状态。
	JobPolling bool `json:"job_polling"`
	// TerminalJobReuse 表示终态任务仍可查询并按幂等键复用。
	TerminalJobReuse bool `json:"terminal_job_reuse"`
	// ForceRequiresNewIdempotencyKey 表示新的 force 执行必须使用新幂等键。
	ForceRequiresNewIdempotencyKey bool `json:"force_requires_new_idempotency_key"`
	// URLs 是服务端公开的 v2 端点模板。
	URLs CapabilitiesURLs `json:"urls"`
}

// DefaultCapabilitiesURLs 返回 v2 的固定端点模板。
func DefaultCapabilitiesURLs() CapabilitiesURLs {
	return CapabilitiesURLs{
		Capabilities: CapabilitiesURL,
		Jobs:         JobsURLTemplate,
		Reconcile:    ReconcileURLTemplate,
		Status:       StatusURLTemplate,
		Manifest:     ManifestURLTemplate,
		Files:        FilesURLTemplate,
		Deployments:  DeploymentsURLTemplate,
	}
}

// DefaultCapabilities 返回当前 v2 生产协议的完整能力声明。
func DefaultCapabilities() Capabilities {
	return Capabilities{
		APIVersion:                     APIVersion,
		AsyncJobs:                      true,
		JobPolling:                     true,
		TerminalJobReuse:               true,
		ForceRequiresNewIdempotencyKey: true,
		URLs:                           DefaultCapabilitiesURLs(),
	}
}

// Validate 严格校验能力声明必须完整支持 v2 冻结语义。
func (c Capabilities) Validate() error {
	if c.APIVersion != APIVersion {
		return protocolError(ErrorCodeInvalidCapabilities, "api_version 必须为 v2")
	}
	if !c.AsyncJobs || !c.JobPolling || !c.TerminalJobReuse || !c.ForceRequiresNewIdempotencyKey {
		return protocolError(ErrorCodeInvalidCapabilities, "v2 capabilities 必须声明异步任务、轮询、终态复用和 force 新幂等键语义")
	}
	return c.URLs.Validate()
}

// UnmarshalJSON 严格解码并校验能力声明。
func (c *Capabilities) UnmarshalJSON(data []byte) error {
	type capabilitiesJSON Capabilities
	var decoded capabilitiesJSON
	if err := unmarshalStrictJSON(data, &decoded); err != nil {
		return err
	}
	capabilities := Capabilities(decoded)
	if err := capabilities.Validate(); err != nil {
		return err
	}
	*c = capabilities
	return nil
}

// MarshalJSON 在编码边界严格校验能力声明。
func (c Capabilities) MarshalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	type capabilitiesJSON Capabilities
	return json.Marshal(capabilitiesJSON(c))
}

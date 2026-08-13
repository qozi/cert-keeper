package certproto

import (
	"net/url"
	"strings"
)

const (
	// V2APIPath 是 v2 公共 API 的路径前缀。
	V2APIPath = "/api/v2"
	// CertificatesPathSegment 是证书资源的 URL 路径段。
	CertificatesPathSegment = "certs"
	// GenerationsPathSegment 是证书 generation 子资源的 URL 路径段。
	GenerationsPathSegment = "generations"
	// FilesPathSegment 是证书文件子资源的 URL 路径段。
	FilesPathSegment = "files"
	// JobsPathSegment 是任务资源的 URL 路径段。
	JobsPathSegment = "jobs"
)

// v2PathSegments 是 V2APIPath 拆分后的单段序列，避免把含分隔符的前缀当作单段校验。
var v2PathSegments = strings.Split(strings.TrimPrefix(V2APIPath, "/"), "/")

// EscapePathSegment 将一个值转义为单个 URL 路径段。
//
// 输入不能为空、不能是 "." 或 ".."，也不能包含路径分隔符；保留字符会由
// url.PathEscape 转义，返回值不会新增路径层级。
func EscapePathSegment(segment string) (string, error) {
	if err := validatePathSegment(segment); err != nil {
		return "", err
	}
	return url.PathEscape(segment), nil
}

// EscapeURLPathSegment 是 EscapePathSegment 的语义别名，便于调用方明确 URL 场景。
func EscapeURLPathSegment(segment string) (string, error) {
	return EscapePathSegment(segment)
}

// BuildURLPath 将多个值安全地转义并拼接成绝对 URL 路径。
func BuildURLPath(segments ...string) (string, error) {
	if len(segments) == 0 {
		return "", protocolError(ErrorCodeInvalidPathSegment, "URL 路径至少需要一个路径段")
	}
	escaped := make([]string, len(segments))
	for i, segment := range segments {
		value, err := EscapePathSegment(segment)
		if err != nil {
			return "", err
		}
		escaped[i] = value
	}
	return "/" + strings.Join(escaped, "/"), nil
}

// v2 路由以 domain 为授权主键，generation 作为其下的不可变版本子资源。

// ReconcileURLPath 构造指定域名 reconcile 的 v2 URL 路径。
func ReconcileURLPath(domain string) (string, error) {
	return BuildURLPath(
		v2PathSegments[0],
		v2PathSegments[1],
		CertificatesPathSegment,
		domain,
		"reconcile",
	)
}

// CertificateStatusURLPath 构造指定域名证书状态的 v2 URL 路径。
func CertificateStatusURLPath(domain string) (string, error) {
	return BuildURLPath(
		v2PathSegments[0],
		v2PathSegments[1],
		CertificatesPathSegment,
		domain,
		"status",
	)
}

// ManifestURLPath 构造指定域名与 generation 的 manifest v2 URL 路径。
func ManifestURLPath(domain, generationID string) (string, error) {
	if err := ValidateGenerationID(generationID); err != nil {
		return "", err
	}
	return BuildURLPath(
		v2PathSegments[0],
		v2PathSegments[1],
		CertificatesPathSegment,
		domain,
		GenerationsPathSegment,
		generationID,
		"manifest",
	)
}

// CertificateFileURLPath 构造指定域名与 generation 下固定证书文件的 v2 URL 路径。
func CertificateFileURLPath(domain, generationID, fileName string) (string, error) {
	if err := ValidateGenerationID(generationID); err != nil {
		return "", err
	}
	if err := ValidateFileName(fileName); err != nil {
		return "", err
	}
	return BuildURLPath(
		v2PathSegments[0],
		v2PathSegments[1],
		CertificatesPathSegment,
		domain,
		GenerationsPathSegment,
		generationID,
		FilesPathSegment,
		fileName,
	)
}

// DeploymentsURLPath 构造指定域名部署回报的 v2 URL 路径。
func DeploymentsURLPath(domain string) (string, error) {
	return BuildURLPath(
		v2PathSegments[0],
		v2PathSegments[1],
		CertificatesPathSegment,
		domain,
		"deployments",
	)
}

// JobURLPath 构造指定任务的 v2 URL 路径。
func JobURLPath(jobID string) (string, error) {
	return BuildURLPath(
		v2PathSegments[0],
		v2PathSegments[1],
		JobsPathSegment,
		jobID,
	)
}

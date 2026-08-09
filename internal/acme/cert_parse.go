// 本文件提供 PEM 格式证书的解析功能。
package acme

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

// ParsePemExpiry 从 PEM 数据中解析第一张证书的有效期。
func ParsePemExpiry(data []byte) (time.Time, error) {
	return parsePemExpiry(data)
}

// parsePemExpiry 从 PEM 数据中解析第一张证书的有效期（内部实现）。
func parsePemExpiry(data []byte) (time.Time, error) {
	// 先尝试作为完整链解析
	if len(data) > 0 {
		if block, _ := pem.Decode(data); block != nil {
			if block.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					return c.NotAfter, nil
				}
			}
		}
	}
	// 回退到 tls.LoadX509KeyPair 风格的解析（解析所有证书）
	certs, err := parsePemChain(data)
	if err != nil {
		return time.Time{}, err
	}
	if len(certs) == 0 {
		return time.Time{}, errors.New("未找到证书")
	}
	return certs[0].NotAfter, nil
}

// parsePemChain 解析 PEM 格式的证书链，返回所有证书。
func parsePemChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("无证书")
	}
	return certs, nil
}

// 用 tls.X509Pair 也行，但保留独立函数
var _ = tls.Config{}

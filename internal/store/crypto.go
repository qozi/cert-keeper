// 本文件提供 v2 机密字段的 AES-256-GCM 加密及本地 KEK 管理。
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const kekSize = 32

const encryptionKeyVersion = 2

const (
	keySourceInjected      = "injected"
	keySourceLegacyFile    = "legacy_file"
	keySourceGeneratedFile = "generated_file"
)

// KeyStatus 是数据库密钥的非敏感状态快照。
type KeyStatus struct {
	Source            string `json:"source"`
	Version           int    `json:"version"`
	Ready             bool   `json:"ready"`
	EncryptedRecords  int    `json:"encrypted_records"`
	UnreadableRecords int    `json:"unreadable_records"`
}

// KeyInfo 是 KeyStatus 的简化只读视图，不包含密钥材料。
type KeyInfo struct {
	Source  string `json:"source"`
	Version int    `json:"version"`
}

// loadOrCreateKEK 为每个数据库创建独立的随机 32 字节 KEK。
// KEK 位于权限为 0600 的同目录文件，使数据库备份不会包含可直接解密的密钥。
func loadOrCreateKEK(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != kekSize {
			return nil, errors.New("数据库密钥长度无效")
		}
		if err := chmodIfSupported(path, 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key = make([]byte, kekSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateKEK(path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return key, nil
}

// loadEncryptionKey 选择环境注入根密钥；旧 .db.kek 只作为迁移回退密钥。
func loadEncryptionKey(dbPath string) (active []byte, source string, version int, legacy []byte, err error) {
	if value := os.Getenv("CK_ENCRYPTION_KEY"); strings.TrimSpace(value) != "" {
		active = deriveKey(value)
		legacy, err = readExistingKEK(dbPath + ".kek")
		if err != nil {
			return nil, "", 0, nil, err
		}
		if len(legacy) == len(active) && string(legacy) == string(active) {
			legacy = nil
		}
		return active, keySourceInjected, encryptionKeyVersion, legacy, nil
	}

	keyPath := dbPath + ".kek"
	if _, statErr := os.Stat(keyPath); statErr == nil {
		active, err = loadOrCreateKEK(keyPath)
		return active, keySourceLegacyFile, encryptionKeyVersion, nil, err
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, "", 0, nil, statErr
	}
	active, err = loadOrCreateKEK(keyPath)
	return active, keySourceGeneratedFile, encryptionKeyVersion, nil, err
}

func readExistingKEK(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(key) != kekSize {
		return nil, errors.New("数据库兼容密钥长度无效")
	}
	if err := chmodIfSupported(path, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// KeyInfo 返回当前密钥来源和版本，不返回密钥内容。
func (s *Store) KeyInfo() KeyInfo {
	return KeyInfo{Source: s.keySource, Version: s.keyVersion}
}

// EncryptionKeyInfo 是 KeyInfo 的兼容命名入口。
func (s *Store) EncryptionKeyInfo() KeyInfo { return s.KeyInfo() }

// KeyStatus 返回密文可解密就绪状态，不返回任何密钥或明文。
func (s *Store) KeyStatus(ctx context.Context) (KeyStatus, error) {
	status := KeyStatus{Source: s.keySource, Version: s.keyVersion, Ready: true}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT 'token', id, '', '', '', secret_ciphertext
		FROM tokens WHERE secret_ciphertext IS NOT NULL
		UNION ALL
		SELECT 'dns', dps.id, dp.provider, dp.profile, dps.env_key, dps.secret_ciphertext
		FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
		WHERE dps.secret_ciphertext IS NOT NULL`)
	if err != nil {
		return KeyStatus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, id, provider, profile, envKey, ciphertext string
		if err := rows.Scan(&kind, &id, &provider, &profile, &envKey, &ciphertext); err != nil {
			return KeyStatus{}, err
		}
		status.EncryptedRecords++
		aad := tokenSecretAAD(id)
		if kind == "dns" {
			aad = dnsSecretAAD(provider, profile, envKey)
		}
		if _, err := decryptAESGCM(ciphertext, s.kek, aad); err != nil {
			status.UnreadableRecords++
		}
	}
	if err := rows.Err(); err != nil {
		return KeyStatus{}, err
	}
	status.Ready = status.UnreadableRecords == 0
	return status, nil
}

// EncryptionKeyStatus 是 KeyStatus 的兼容命名入口。
func (s *Store) EncryptionKeyStatus(ctx context.Context) (KeyStatus, error) {
	return s.KeyStatus(ctx)
}

// CheckEncryptionReadiness 校验所有 v2 密文都能由当前根密钥解密。
func (s *Store) CheckEncryptionReadiness(ctx context.Context) error {
	status, err := s.KeyStatus(ctx)
	if err != nil {
		return fmt.Errorf("检查数据库密文就绪状态失败: %w", err)
	}
	if !status.Ready {
		return errors.New("数据库存在无法解密的机密记录")
	}
	return nil
}

// EncryptionReady 返回密文是否全部可由当前根密钥解密。
func (s *Store) EncryptionReady(ctx context.Context) (bool, error) {
	status, err := s.KeyStatus(ctx)
	if err != nil {
		return false, err
	}
	return status.Ready, nil
}

func (s *Store) saveKeyMetadata(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO encryption_metadata(id, key_source, key_version, updated_at) VALUES(1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET key_source=excluded.key_source,
		  key_version=excluded.key_version, updated_at=excluded.updated_at`,
		s.keySource, s.keyVersion, timeNowUnix())
	return err
}

func timeNowUnix() int64 { return time.Now().Unix() }

// migrateLegacyCiphertexts 将旧 .db.kek 或 v1 明文 token 迁移到当前根密钥。
func (s *Store) migrateLegacyCiphertexts(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, secret, secret_ciphertext FROM tokens ORDER BY id`)
	if err != nil {
		return err
	}
	type tokenRecord struct {
		id, secret, ciphertext string
		secretValid            bool
		ciphertextValid        bool
	}
	var tokens []tokenRecord
	for rows.Next() {
		var item tokenRecord
		var secret, ciphertext sql.NullString
		if err := rows.Scan(&item.id, &secret, &ciphertext); err != nil {
			return err
		}
		item.secret, item.secretValid = secret.String, secret.Valid
		item.ciphertext, item.ciphertextValid = ciphertext.String, ciphertext.Valid
		tokens = append(tokens, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, item := range tokens {
		if err := ctx.Err(); err != nil {
			return err
		}
		if item.ciphertextValid && item.ciphertext != "" {
			if _, err := decryptAESGCM(item.ciphertext, s.kek, tokenSecretAAD(item.id)); err == nil {
				continue
			} else if len(s.legacyKEK) == 0 {
				continue
			}
			plain, decryptErr := decryptAESGCM(item.ciphertext, s.legacyKEK, tokenSecretAAD(item.id))
			if decryptErr != nil {
				continue
			}
			ciphertext, encryptErr := encryptAESGCM(plain, s.kek, tokenSecretAAD(item.id))
			if encryptErr != nil {
				return encryptErr
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE tokens SET secret_ciphertext=?, secret=NULL WHERE id=?`, ciphertext, item.id); err != nil {
				return err
			}
			continue
		}
		if item.secretValid && item.secret != "" {
			ciphertext, err := encryptAESGCM(item.secret, s.kek, tokenSecretAAD(item.id))
			if err != nil {
				return err
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE tokens SET secret_ciphertext=?, secret=NULL, secret_version=?, secret_rotated_at=? WHERE id=?`,
				ciphertext, tokenSecretVersion, timeNowUnix(), item.id); err != nil {
				return err
			}
		}
	}

	rows, err = s.DB.QueryContext(ctx, `
		SELECT dps.id, dp.provider, dp.profile, dps.env_key, dps.secret_ciphertext
		FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
		ORDER BY dps.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type dnsRecord struct {
		id                        int64
		provider, profile, envKey string
		ciphertext                string
	}
	var dnsRecords []dnsRecord
	for rows.Next() {
		var item dnsRecord
		if err := rows.Scan(&item.id, &item.provider, &item.profile, &item.envKey, &item.ciphertext); err != nil {
			return err
		}
		dnsRecords = append(dnsRecords, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, item := range dnsRecords {
		if err := ctx.Err(); err != nil {
			return err
		}
		aad := dnsSecretAAD(item.provider, item.profile, item.envKey)
		if _, err := decryptAESGCM(item.ciphertext, s.kek, aad); err == nil {
			continue
		} else if len(s.legacyKEK) == 0 {
			continue
		}
		plain, decryptErr := decryptAESGCM(item.ciphertext, s.legacyKEK, aad)
		if decryptErr != nil {
			continue
		}
		ciphertext, encryptErr := encryptAESGCM(plain, s.kek, aad)
		if encryptErr != nil {
			return encryptErr
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE dns_profile_secrets SET secret_ciphertext=?, updated_at=? WHERE id=?`, ciphertext, timeNowUnix(), item.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) decryptStoredSecret(ciphertext string, aad []byte) (string, error) {
	plain, err := decryptAESGCM(ciphertext, s.kek, aad)
	if err == nil {
		return plain, nil
	}
	if len(s.legacyKEK) > 0 {
		if plain, legacyErr := decryptAESGCM(ciphertext, s.legacyKEK, aad); legacyErr == nil {
			return plain, nil
		}
	}
	return "", errors.New("无法验证或解密机密")
}

func (s *Store) clearKeys() {
	for i := range s.kek {
		s.kek[i] = 0
	}
	for i := range s.legacyKEK {
		s.legacyKEK[i] = 0
	}
	s.kek = nil
	s.legacyKEK = nil
}

func encryptAESGCM(plain string, key, aad []byte) (string, error) {
	if len(key) != kekSize {
		return "", errors.New("AES-256 密钥长度无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), aad)), nil
}

func decryptAESGCM(ciphertext string, key, aad []byte) (string, error) {
	if len(key) != kekSize {
		return "", errors.New("AES-256 密钥长度无效")
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("密文编码无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("密文长度不足")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
	if err != nil {
		return "", errors.New("无法验证或解密机密")
	}
	return string(plain), nil
}

func tokenSecretAAD(id string) []byte {
	return []byte(fmt.Sprintf("certkeeper/tokens/v2/id=%s", id))
}

func dnsSecretAAD(provider, profile, envKey string) []byte {
	return []byte(fmt.Sprintf("certkeeper/dns-profiles/v2/provider=%s/profile=%s/env_key=%s", provider, profile, envKey))
}

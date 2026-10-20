/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
*/

package sshkey

import (
	"strings"
	"testing"

	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8K1ZuSC7tmzxD5LJJXwkCfStVEjzXWYCFhJaLBxWAn test@example.com"

func sshKeySecret(secretType privatev1.SecretType, data map[string][]byte) *privatev1.Secret {
	return privatev1.Secret_builder{
		Id:       "key-id",
		Metadata: privatev1.Metadata_builder{Name: "key-name", Tenant: "tenant1"}.Build(),
		Type:     secretType,
		Data:     data,
	}.Build()
}

func TestValidateSecretData(t *testing.T) {
	t.Run("accepts a well-formed SSH-key Secret", func(t *testing.T) {
		secret := sshKeySecret(privatev1.SecretType_SECRET_TYPE_SSH_PUBLIC_KEY,
			map[string][]byte{PublicKeyDataKey: []byte(testKey)})
		if err := ValidateSecretData(secret, secret.GetData(), "key-id"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects a wrong-type Secret", func(t *testing.T) {
		secret := sshKeySecret(privatev1.SecretType_SECRET_TYPE_USER_DATA,
			map[string][]byte{"userdata": []byte("#cloud-config")})
		err := ValidateSecretData(secret, secret.GetData(), "key-id")
		if err == nil || !strings.Contains(err.Error(), "expected SECRET_TYPE_SSH_PUBLIC_KEY") {
			t.Fatalf("expected a type error, got: %v", err)
		}
	})

	t.Run("rejects an empty public_key entry", func(t *testing.T) {
		secret := sshKeySecret(privatev1.SecretType_SECRET_TYPE_SSH_PUBLIC_KEY, nil)
		err := ValidateSecretData(secret, secret.GetData(), "key-id")
		if err == nil || !strings.Contains(err.Error(), "public_key") {
			t.Fatalf("expected an empty-entry error, got: %v", err)
		}
	})

	t.Run("rejects malformed key material without echoing it", func(t *testing.T) {
		secret := sshKeySecret(privatev1.SecretType_SECRET_TYPE_SSH_PUBLIC_KEY,
			map[string][]byte{PublicKeyDataKey: []byte("not-a-key")})
		err := ValidateSecretData(secret, secret.GetData(), "key-id")
		if err == nil || !strings.Contains(err.Error(), "invalid OpenSSH public key") {
			t.Fatalf("expected a format error, got: %v", err)
		}
		if strings.Contains(err.Error(), testKey) {
			t.Fatalf("error leaks key material: %v", err)
		}
	})
}

package auth

import (
	"strings"
	"testing"
)

func TestPasswordRoundTripAndSalt(t *testing.T) {
	first, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("password hashes must use independent salts")
	}
	if !strings.HasPrefix(first, "$argon2id$v=19$") {
		t.Fatalf("unexpected encoding: %q", first)
	}
	if !VerifyPassword(first, "correct horse battery staple") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(first, "wrong password") {
		t.Fatal("invalid password accepted")
	}
}

func TestPasswordPolicyAllowsAnyEightCharacters(t *testing.T) {
	for _, password := range []string{"12345678", "abcdefgh", "!!!!!!!!", "пароль12"} {
		if err := validatePassword(password); err != nil {
			t.Fatalf("8-character password %q rejected: %v", password, err)
		}
	}
	if err := validatePassword("1234567"); err == nil {
		t.Fatal("7-character password accepted")
	}
}

func TestPasswordRejectsMalformedHash(t *testing.T) {
	for _, encoded := range []string{"", "sha256:abc", "$argon2id$broken", "$argon2id$v=19$m=1,t=1,p=1$bad$bad"} {
		if VerifyPassword(encoded, "anything") {
			t.Fatalf("malformed hash accepted: %q", encoded)
		}
	}
}

package oidc

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestGoMleOidc(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "go-oidc-mle suite")
}

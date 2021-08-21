package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	GroupName string = "dolansoft.org"
	Kind      string = "SecretClaim"
	Version   string = "v1beta1"
	Plural    string = "secretclaims"
	Singluar  string = "secretclaim"
	ShortName string = "secc"
	Name      string = Plural + "." + GroupName
)

type X509Claim struct {
	CASecretName         string   `json:"caSecretName"`
	IsCA                 bool     `json:"isCA"`
	CommonName           string   `json:"commonName"`
	RotateEvery          string   `json:"rotateEvery"`
	ServiceNames         []string `json:"serviceNames"`
	ExtraNames           []string `json:"extraNames"`
	LegacySEC1PrivateKey bool     `json:"legacySEC1PrivateKey"`
}

type SecretClaimSpec struct {
	TokenFields []string          `json:"tokenFields"`
	FixedFields map[string]string `json:"fixedFields"`
	X509Claim   *X509Claim        `json:"x509,omitempty"`
}

type SecretClaimStatus struct {
	Reason string `json:"reason,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SecretClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretClaimSpec   `json:"spec"`
	Status SecretClaimStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SecretClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []SecretClaim `json:"items"`
}

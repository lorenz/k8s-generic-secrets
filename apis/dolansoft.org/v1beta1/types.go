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

type SecretClaimSpec struct {
	TokenFields []string          `json:"tokenFields"`
	FixedFields map[string]string `json:"fixedFields"`
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

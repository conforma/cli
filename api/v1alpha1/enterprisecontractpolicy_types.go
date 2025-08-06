/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Important: Run "make" to regenerate code after modifying this file
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EnterpriseContractPolicySpec is used to configure the Enterprise Contract Policy
type EnterpriseContractPolicySpec struct {
	// Optional name of the policy
	// +optional
	Name string `json:"name,omitempty"`
	// Description of the policy or its intended use
	// +optional
	Description string `json:"description,omitempty"`
	// One or more groups of policy rules
	// +kubebuilder:validation:MinItems:=1
	Sources []Source `json:"sources,omitempty"`
	// Configuration handles policy modification configuration (exclusions and inclusions)
	// +optional
	Configuration *EnterpriseContractPolicyConfiguration `json:"configuration,omitempty"`
	// URL of the Rekor instance. Empty string disables Rekor integration
	// +optional
	RekorUrl string `json:"rekorUrl,omitempty"`
	// Public key used to validate the signature of images and attestations
	// +optional
	PublicKey string `json:"publicKey,omitempty"`
	// Identity to be used for keyless verification. This is an experimental feature.
	// +optional
	Identity *Identity `json:"identity,omitempty"`
}

// Source defines policies and data that are evaluated together
type Source struct {
	// Optional name for the source
	// +optional
	Name string `json:"name,omitempty"`
	// List of go-getter style policy source urls
	// +kubebuilder:validation:MinItems:=1
	Policy []string `json:"policy,omitempty"`
	// List of go-getter style policy data source urls
	// +optional
	Data []string `json:"data,omitempty"`
	// Arbitrary rule data that will be visible to policy rules
	// +optional
	// +kubebuilder:validation:Type:=object
	RuleData *extv1.JSON `json:"ruleData,omitempty"`
	// Config specifies which policy rules are included, or excluded, from the
	// provided policy source urls.
	// +optional
	// +kubebuilder:validation:Type:=object
	Config *SourceConfig `json:"config,omitempty"`
	// Specifies volatile configuration that can include or exclude policy rules
	// based on effective time.
	// +optional
	// +kubebuilder:validation:Type:=object
	VolatileConfig *VolatileSourceConfig `json:"volatileConfig,omitempty"`
}

// SourceConfig specifies config options for a policy source.
type SourceConfig struct {
	// Exclude is a set of policy exclusions that, in case of failure, do not block
	// the success of the outcome.
	// +optional
	// +listType:=set
	Exclude []string `json:"exclude,omitempty"`
	// Include is a set of policy inclusions that are added to the policy evaluation.
	// These take precedence over policy exclusions.
	// +optional
	// +listType:=set
	Include []string `json:"include,omitempty"`
}

// VolatileCriteria includes or excludes a policy rule with effective dates as an option.
type VolatileCriteria struct {
	Value string `json:"value"`
	// +optional
	// +kubebuilder:validation:Format:=date-time
	EffectiveOn string `json:"effectiveOn,omitempty"`
	// +optional
	// +kubebuilder:validation:Format:=date-time
	EffectiveUntil string `json:"effectiveUntil,omitempty"`

	// DEPRECATED: Use ImageDigest instead
	// ImageRef is used to specify an image by its digest.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[a-fA-F0-9]{64}$`
	ImageRef string `json:"imageRef,omitempty"`

	// ImageDigest is used to specify an image by its digest.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[a-fA-F0-9]{64}$`
	ImageDigest string `json:"imageDigest,omitempty"`

	// ImageUrl is used to specify an image by its URL without a tag.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9.-]*[a-z0-9](?:\/[a-z0-9][a-z0-9-]*[a-z0-9]){2,}$`
	ImageUrl string `json:"imageUrl,omitempty"`

	// Reference is used to include a link to related information such as a Jira issue URL.
	// +optional
	Reference string `json:"reference,omitempty"`
}

// VolatileSourceConfig specifies volatile configuration for a policy source.
type VolatileSourceConfig struct {
	// Exclude is a set of policy exclusions that, in case of failure, do not block
	// the success of the outcome.
	// +optional
	Exclude []VolatileCriteria `json:"exclude,omitempty"`
	// Include is a set of policy inclusions that are added to the policy evaluation.
	// These take precedence over policy exclusions.
	// +optional
	Include []VolatileCriteria `json:"include,omitempty"`
}

// EnterpriseContractPolicyConfiguration configuration of modifications to policy evaluation.
// DEPRECATED: Use the config for a policy source instead.
type EnterpriseContractPolicyConfiguration struct {
	// Exclude set of policy exclusions that, in case of failure, do not block
	// the success of the outcome.
	// +optional
	// +listType:=set
	Exclude []string `json:"exclude,omitempty"`
	// Include set of policy inclusions that are added to the policy evaluation.
	// These override excluded rules.
	// +optional
	// +listType:=set
	Include []string `json:"include,omitempty"`
	// Collections set of predefined rules.  DEPRECATED: Collections can be listed in include
	// with the "@" prefix.
	// +optional
	// +listType:=set
	Collections []string `json:"collections,omitempty"`
}

// Identity defines the allowed identity for keyless signing.
type Identity struct {
	// Subject is the URL of the certificate identity for keyless verification.
	// +optional
	Subject string `json:"subject,omitempty"`
	// SubjectRegExp is a regular expression to match the URL of the certificate identity for
	// keyless verification.
	// +optional
	SubjectRegExp string `json:"subjectRegExp,omitempty"`
	// Issuer is the URL of the certificate OIDC issuer for keyless verification.
	// +optional
	Issuer string `json:"issuer,omitempty"`
	// IssuerRegExp is a regular expression to match the URL of the certificate OIDC issuer for
	// keyless verification.
	// +optional
	IssuerRegExp string `json:"issuerRegExp,omitempty"`
}

// EnterpriseContractPolicyStatus defines the observed state of EnterpriseContractPolicy
type EnterpriseContractPolicyStatus struct {
	// TODO what to add here?
	// ideas;
	// - on what the policy was applied
	// - history of changes
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:categories={all},shortName={ecp}
// +kubebuilder:subresource:status
// EnterpriseContractPolicy is the Schema for the enterprisecontractpolicies API
type EnterpriseContractPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EnterpriseContractPolicySpec   `json:"spec,omitempty"`
	Status EnterpriseContractPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EnterpriseContractPolicyList contains a list of EnterpriseContractPolicy
type EnterpriseContractPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EnterpriseContractPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EnterpriseContractPolicy{}, &EnterpriseContractPolicyList{})
}

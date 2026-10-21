package lib.release

import rego.v1

allowed_signer(signer) if {
	data.allowed_signers[_] == signer
}

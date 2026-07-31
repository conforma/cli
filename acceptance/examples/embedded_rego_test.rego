package main

import data.ec_lib

# METADATA
# custom:
#   short_name: embedded_test
deny contains result if {
	# Always deny
	true

	# We're expecting this to be defined in the "embedded" rego
	msg := ec_lib.hello_world("testy mctest")

	result := {"code": "main.embedded_test", "msg": msg}
}

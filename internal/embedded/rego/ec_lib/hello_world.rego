package ec_lib

# Simple POC to demonstrate the idea of embedding rego in the cli
hello_world(name) := sprintf("Hello, %s! (from embedded rego)", [name])

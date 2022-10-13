 signing-samples

This repo is a sample repository for the different signing solutions.

The solution only use the base identity and encryption Microsoft libraries.

Currently supported signings:
- JWT signing
- XML signing
- XML signing with ds: prefix at signatures

# Test cases:
 - ##  JWTTests
	- SignAndVerify: Signing and verifying a custom JWT token
	- JWKSTest: Create and sign a JWT token, after that create a JWKS string from the public key of the signing certificate, than this JWKS used for the signed token verification
- ## XMLTests:
	- SignAndVerify: Sign a simple xml text with the sample certification
- ## XMLDSTests:
	- SignAndVerify: Sign a simple xml text with the sample certification, but the ***SignatureValue*** namespace changed to ***ds:SignatureValue***

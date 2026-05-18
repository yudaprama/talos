package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/spf13/cobra"
)

// rsaAlgorithmAllowlist is the set of signature algorithms valid for RSA keys.
var rsaAlgorithmAllowlist = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// newJWKCmd creates the jwk command group for generating JWK/JWKS files
func newJWKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwk",
		Short: "Generate JSON Web Keys (JWK/JWKS)",
		Long: `Generate cryptographic keys in JSON Web Key (JWK) format.
Supports EdDSA (Ed25519), ECDSA (P-256, P-384, P-521), RSA, and HMAC algorithms.`,
	}

	// Add subcommands for key generation and fetching
	cmd.AddCommand(newJWKGenerateCmd())
	cmd.AddCommand(newGetJWKSCmd())

	return cmd
}

// newJWKGenerateCmd creates the generate command with subcommands for each algorithm
func newJWKGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new JWK key",
		Long:  `Generate a new cryptographic key in JWK format for signing or encryption.`,
	}

	// Add algorithm-specific subcommands
	cmd.AddCommand(newJWKGenerateEdDSACmd())
	cmd.AddCommand(newJWKGenerateECDSACmd())
	cmd.AddCommand(newJWKGenerateRSACmd())
	cmd.AddCommand(newJWKGenerateHMACCmd())

	return cmd
}

// Common flags for all key generation commands
type jwkGenerateFlags struct {
	kid        string
	use        string
	alg        string
	output     string
	publicOnly bool
	jwks       bool
}

// newJWKGenerateEdDSACmd creates the command for generating EdDSA (Ed25519) keys
func newJWKGenerateEdDSACmd() *cobra.Command {
	var flags jwkGenerateFlags

	cmd := &cobra.Command{
		Use:   "eddsa",
		Short: "Generate an EdDSA (Ed25519) key pair",
		Long: `Generate an EdDSA key pair using the Ed25519 curve.
Ed25519 uses a fixed 256-bit key size.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Generate Ed25519 key pair
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return errors.Wrap(err, "generate Ed25519 key pair")
			}

			return finalizeAndOutputJWK(cmd, priv, jwa.EdDSA(), flags)
		},
	}

	cmd.Example = `  # Generate with auto-generated key ID
  {{ .CommandPath }} -o signing-key.json

  # Generate with custom key ID
  {{ .CommandPath }} --kid prod-key-1 -o signing-key.json

  # Generate public key only
  {{ .CommandPath }} --public-only -o public-key.json

  # Generate as JWKS format
  {{ .CommandPath }} --jwks -o keys.jwks.json`

	addJWKGenerateFlags(cmd, &flags)
	addPublicOnlyFlag(cmd, &flags)
	return cmd
}

// newJWKGenerateECDSACmd creates the command for generating ECDSA keys
func newJWKGenerateECDSACmd() *cobra.Command {
	var flags jwkGenerateFlags
	var curve string

	cmd := &cobra.Command{
		Use:   "ecdsa",
		Short: "Generate an ECDSA key pair",
		Long: `Generate an ECDSA key pair using the specified elliptic curve.
Key size is determined by the curve: P-256 (256-bit), P-384 (384-bit), P-521 (521-bit).
Default curve: P-256.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Select curve
			var ecCurve elliptic.Curve
			var alg jwa.SignatureAlgorithm
			switch curve {
			case "P-256", "p256", "":
				ecCurve = elliptic.P256()
				alg = jwa.ES256()
			case "P-384", "p384":
				ecCurve = elliptic.P384()
				alg = jwa.ES384()
			case "P-521", "p521":
				ecCurve = elliptic.P521()
				alg = jwa.ES512()
			default:
				return errors.Errorf("unsupported curve: %s (must be P-256, P-384, or P-521)", curve)
			}

			// Generate ECDSA key pair
			priv, err := ecdsa.GenerateKey(ecCurve, rand.Reader)
			if err != nil {
				return errors.Wrap(err, "generate ECDSA key pair")
			}

			return finalizeAndOutputJWK(cmd, priv, alg, flags)
		},
	}

	cmd.Example = `  # Generate P-256 key (default)
  {{ .CommandPath }} -o ecdsa-key.json

  # Generate P-384 key with custom key ID
  {{ .CommandPath }} --curve P-384 --kid prod-ec-key -o ecdsa-p384.json

  # Generate P-521 key
  {{ .CommandPath }} --curve P-521 -o ecdsa-p521.json`

	addJWKGenerateFlags(cmd, &flags)
	addPublicOnlyFlag(cmd, &flags)
	cmd.Flags().StringVar(&curve, "curve", "P-256", "Elliptic curve (P-256, P-384, P-521)")
	return cmd
}

// newJWKGenerateRSACmd creates the command for generating RSA keys
func newJWKGenerateRSACmd() *cobra.Command {
	var flags jwkGenerateFlags
	var bits int

	cmd := &cobra.Command{
		Use:   "rsa",
		Short: "Generate an RSA key pair",
		Long: `Generate an RSA key pair with the specified key size.
Default is 2048 bits. Minimum is 2048 bits.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Validate key size
			if bits < 2048 {
				return errors.Errorf("key size %d is below minimum of 2048 bits", bits)
			}
			// Enforce maximum key size
			if bits > 8192 {
				return errors.Errorf("key size %d exceeds maximum of 8192 bits", bits)
			}
			// Validate algorithm is RSA-compatible
			if flags.alg != "" && !rsaAlgorithmAllowlist[flags.alg] {
				return errors.Errorf("algorithm %q is not valid for RSA keys; must be one of RS256, RS384, RS512, PS256, PS384, PS512", flags.alg)
			}

			// Generate RSA key pair
			priv, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				return errors.Wrap(err, "generate RSA key pair")
			}

			return finalizeAndOutputJWK(cmd, priv, jwa.RS256(), flags)
		},
	}

	cmd.Example = `  # Generate RSA key (default: 2048 bits)
  {{ .CommandPath }} -o rsa-key.json

  # Generate 4096-bit RSA key
  {{ .CommandPath }} --bits 4096 -o rsa-4096.json

  # Generate with custom algorithm
  {{ .CommandPath }} --alg RS512 -o rsa-rs512.json

  # Generate public key only
  {{ .CommandPath }} --public-only -o rsa-public.json`

	addJWKGenerateFlags(cmd, &flags)
	addPublicOnlyFlag(cmd, &flags)
	addAlgFlag(cmd, &flags)
	cmd.Flags().IntVar(&bits, "bits", 2048, "Key size in bits (minimum 2048)")
	return cmd
}

// newJWKGenerateHMACCmd creates the command for generating HMAC secrets
func newJWKGenerateHMACCmd() *cobra.Command {
	var flags jwkGenerateFlags
	var bits int

	cmd := &cobra.Command{
		Use:   "hmac",
		Short: "Generate an HMAC secret key",
		Long: `Generate a symmetric HMAC secret key.
Default size is 512 bits. Minimum is 256 bits.
Algorithm is determined by key size: 256→HS256, 384→HS384, ≥512→HS512.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Validate key size
			if bits%8 != 0 {
				return errors.Errorf("key size must be a multiple of 8, got %d", bits)
			}
			if bits < 256 {
				return errors.Errorf("key size %d is below minimum of 256 bits", bits)
			}

			// Generate random bytes
			secret := make([]byte, bits/8)
			if _, err := rand.Read(secret); err != nil {
				return errors.Wrap(err, "generate random secret")
			}

			// Create JWK from secret
			key, err := jwk.Import(secret)
			if err != nil {
				return errors.Wrap(err, "create JWK from secret")
			}

			// Set key type to oct (octet sequence)
			if err := key.Set(jwk.KeyTypeKey, jwa.OctetSeq()); err != nil {
				return errors.Wrap(err, "set key type")
			}

			// Set key ID (uses JWK Thumbprint if not provided)
			if err := setKeyID(key, flags.kid); err != nil {
				return err
			}

			// Set algorithm (based on secret size)
			alg := jwa.HS256()
			if bits == 384 {
				alg = jwa.HS384()
			} else if bits >= 512 {
				alg = jwa.HS512()
			}
			if err := setAlgorithm(key, "", alg); err != nil {
				return err
			}

			// Set key usage (defaults to signing)
			if err := setKeyUsage(key, flags.use); err != nil {
				return err
			}

			return outputJWK(cmd, key, flags)
		},
	}

	cmd.Example = `  # Generate 512-bit HMAC secret (default)
  {{ .CommandPath }} -o hmac-secret.json

  # Generate 256-bit HMAC secret
  {{ .CommandPath }} --bits 256 -o hmac-256.json

  # Generate with custom key ID
  {{ .CommandPath }} --kid signing-secret-1 -o hmac-key.json`

	addJWKGenerateFlags(cmd, &flags)
	cmd.Flags().IntVar(&bits, "bits", 512, "Key size in bits (default 512, minimum 256)")
	return cmd
}

// addJWKGenerateFlags adds flags shared by all key generation commands.
func addJWKGenerateFlags(cmd *cobra.Command, flags *jwkGenerateFlags) {
	cmd.Flags().StringVar(&flags.kid, "kid", "", "Key ID (JWK Thumbprint used if not provided)")
	cmd.Flags().StringVar(&flags.use, "use", "", "Key usage: 'sig' for signing, 'enc' for encryption (default: sig)")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Output file (writes to stdout if not specified)")
	cmd.Flags().BoolVar(&flags.jwks, "jwks", false, "Output as JWKS (JSON Web Key Set)")
}

// addPublicOnlyFlag adds the --public-only flag to asymmetric key generation commands.
// Not applicable to symmetric keys (HMAC) which have no public key.
func addPublicOnlyFlag(cmd *cobra.Command, flags *jwkGenerateFlags) {
	cmd.Flags().BoolVar(&flags.publicOnly, "public-only", false, "Output public key only")
}

// addAlgFlag adds the --alg flag to commands where the algorithm can be meaningfully
// overridden. Only applicable to RSA, which supports multiple algorithms (RS256/384/512,
// PS256/384/512). For EdDSA, ECDSA, and HMAC the algorithm is determined by the key
// type, curve, or bit size respectively and cannot be changed independently.
func addAlgFlag(cmd *cobra.Command, flags *jwkGenerateFlags) {
	cmd.Flags().StringVar(&flags.alg, "alg", "", "Algorithm override (e.g. RS384, RS512, PS256)")
}

// setKeyID sets the Key ID on the JWK. If not provided in flags, uses the JWK Thumbprint (RFC 7638).
func setKeyID(key jwk.Key, flagKID string) error {
	kid := flagKID
	if kid == "" {
		// Generate key ID from JWK Thumbprint (RFC 7638)
		// Compute SHA256 of the public key's JSON representation
		pubKey := key
		if key.KeyType().String() != "oct" { // Not symmetric
			pk, err := key.PublicKey()
			if err != nil {
				return errors.Wrap(err, "extract public key for thumbprint")
			}
			pubKey = pk
		}

		// Marshal to JSON and compute SHA256
		jsonBytes, err := json.Marshal(pubKey)
		if err != nil {
			return errors.Wrap(err, "marshal key for thumbprint")
		}

		// Compute SHA256 and base64-encode
		hash := sha256.Sum256(jsonBytes)
		kid = base64.URLEncoding.EncodeToString(hash[:])
	}
	return errors.Wrap(key.Set(jwk.KeyIDKey, kid), "set key ID")
}

// setAlgorithm sets the algorithm on the JWK. Uses provided flag if set, otherwise uses default.
func setAlgorithm(key jwk.Key, algFlag string, defaultAlg jwa.SignatureAlgorithm) error {
	alg := defaultAlg
	if algFlag != "" {
		var ok bool
		alg, ok = jwa.LookupSignatureAlgorithm(algFlag)
		if !ok {
			return errors.Errorf("unknown signature algorithm: %s", algFlag)
		}
	}
	return errors.Wrap(key.Set(jwk.AlgorithmKey, alg), "set algorithm")
}

// setKeyUsage sets the key usage on the JWK. Defaults to "sig" if not provided.
func setKeyUsage(key jwk.Key, useFlag string) error {
	use := useFlag
	if use == "" {
		use = "sig" // Default to signing
	}
	return errors.Wrap(key.Set(jwk.KeyUsageKey, use), "set key usage")
}

// newGetJWKSCmd creates the command for fetching the server's JWKS.
func newGetJWKSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "get",
		Short:        "Fetch the server's JSON Web Key Set (JWKS)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverAddr, err := cmd.Flags().GetString("endpoint")
			if err != nil {
				return errors.Wrap(err, "read endpoint flag")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).APIKeysAPI.
				GetJWKS(ctx).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return errors.Wrap(err, "fetch JWKS")
			}

			jwksJSON, err := json.MarshalIndent(resp.GetJwks(), "", "  ")
			if err != nil {
				return errors.Wrap(err, "format JWKS")
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(jwksJSON))

			return nil
		},
	}

	return cmd
}

// finalizeAndOutputJWK imports a raw cryptographic key into a JWK, sets standard
// metadata (key ID, algorithm, usage), extracts the public key if requested, and
// writes the result. Used by EdDSA, ECDSA, and RSA generation commands.
func finalizeAndOutputJWK(cmd *cobra.Command, rawKey any, defaultAlg jwa.SignatureAlgorithm, flags jwkGenerateFlags) error {
	key, err := jwk.Import(rawKey)
	if err != nil {
		return errors.Wrap(err, "create JWK from key")
	}

	if err := setKeyID(key, flags.kid); err != nil {
		return err
	}

	if err := setAlgorithm(key, flags.alg, defaultAlg); err != nil {
		return err
	}

	if err := setKeyUsage(key, flags.use); err != nil {
		return err
	}

	outputKey := key
	if flags.publicOnly {
		pubKey, err := key.PublicKey()
		if err != nil {
			return errors.Wrap(err, "extract public key")
		}
		outputKey = pubKey
	}

	return outputJWK(cmd, outputKey, flags)
}

// outputJWK writes the JWK to the specified output (stdout or file)
func outputJWK(cmd *cobra.Command, key jwk.Key, flags jwkGenerateFlags) error {
	var jsonBytes []byte
	var err error

	if flags.jwks {
		// Create a JWKS (key set) with a single key
		set := jwk.NewSet()
		if err := set.AddKey(key); err != nil {
			return errors.Wrap(err, "add key to set")
		}

		jsonBytes, err = json.MarshalIndent(set, "", "  ")
		if err != nil {
			return errors.Wrap(err, "marshal JWKS")
		}
	} else {
		// Output as single JWK
		jsonBytes, err = json.MarshalIndent(key, "", "  ")
		if err != nil {
			return errors.Wrap(err, "marshal JWK")
		}
	}

	// Write to output
	if flags.output != "" {
		// Write to file
		if err := os.WriteFile(flags.output, jsonBytes, 0o600); err != nil {
			return errors.Wrapf(err, "write to file %s", flags.output)
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "JWK written to %s\n", flags.output)
	} else {
		// Write to stdout (parsable data)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(jsonBytes))
	}

	// Log key details to stderr
	var kid, kty, alg any
	_ = key.Get(jwk.KeyIDKey, &kid)
	_ = key.Get(jwk.AlgorithmKey, &alg)
	_ = key.Get(jwk.KeyTypeKey, &kty)

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Key ID: %v\n", kid)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Key Type: %v\n", kty)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Algorithm: %v\n", alg)

	return nil
}

// reviewed - @aeneasr - 2026-03-25

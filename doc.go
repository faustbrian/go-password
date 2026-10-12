// Package password provides bounded Argon2id and bcrypt password hashing,
// verification, parsing, and explicit login-time upgrades. It does not own
// users, credential storage, sessions, authorization, or persistence.
//
// Construct a complete Policy with NewPolicy or use DefaultPolicy, then New.
// The target selects new hashes; verification accepts either supported algorithm
// within the policy limits. Password bytes are used exactly as supplied, without
// normalization or pre-hashing, and must remain stable until a call returns.
//
// Contexts cancel entry and admission waits, not started cryptographic work.
// Applications own resource sizing, authentication responses, and durable CAS
// upgrades. EncodedHash.String and Error.Cause expose sensitive persistence or
// operational data; diagnostic redaction is not a general serialization policy.
package password

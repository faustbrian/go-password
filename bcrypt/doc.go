// Package bcrypt provides bcrypt-target constructors for compatibility work.
// Returned services can verify bounded Argon2id hashes but never recommend an
// Argon2id-to-bcrypt replacement. Bcrypt hashing and verification limit passwords
// to 72 bytes; no normalization, pre-hashing, or silent truncation is applied.
package bcrypt

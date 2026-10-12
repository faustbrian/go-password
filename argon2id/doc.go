// Package argon2id provides constructors selecting Argon2id for new hashes
// and upgrades. Returned password services still verify bounded bcrypt hashes.
// Policy limits, caller-owned password bytes, admission, and non-interruptible
// primitive contracts are those of the root password package.
package argon2id

# password

Hash passwords with Argon2id and verify Argon2id or legacy bcrypt hashes.
The package uses `golang.org/x/crypto` for the cryptography and stores
Argon2id hashes as PHC strings, with the salt and parameters in each hash.

```go
import "github.com/17xande-dev/password"

// On password creation, after the app has applied its policy:
hash, err := password.Hash(ctx, plaintext)

// On sign-in, after fetching the stored hash:
ok, rehash, err := password.Check(ctx, storedHash, plaintext)
```

Check `err` separately from `ok`: a malformed hash is an operator problem,
not an ordinary mismatch. `Validate` checks a precomputed hash before storing
it, without running the KDF. `rehash` is true only on a match; callers that
upgrade on login can hash again and replace the stored hash if it hasn't
changed concurrently.

For unknown users, call `password.CheckDummy(ctx, plaintext)` and return the
same login failure as for a wrong password. It never matches and spends one
check at the current Argon2id settings. It does not match the timing of
legacy hashes that use different parameters or bcrypt.

## Why extract this?

Several independent implementations drifted over time. Some had no
concurrency cap: at about 64 MiB per default Argon2id operation, a burst of
logins can take down a memory-limited server.
`Hash`, `Check`, and `CheckDummy` share one process-wide cap. It defaults to
`max(2, min(runtime.NumCPU(), 4))`; tune it for the memory available in production
with `SetConcurrency` **before serving**. In-flight calls retain their old
semaphore, so resizing during traffic can temporarily exceed the new limit.
This cap does not replace login rate limits.

Context cancellation and deadlines bound the wait for a slot, not the KDF
once started. A wait failure matches both `password.ErrBusy` and the context
error via `errors.Is`. To limit queueing to two seconds, pass a context made
with `context.WithTimeout(ctx, 2*time.Second)`.

New hashes use 64 MiB, three passes, four lanes, a 16-byte salt, and a 32-byte
key. Old hashes verify at their own settings within the parser's safety limits
(Argon2id: at most 1 GiB, 10 passes and 16 lanes; bcrypt: cost 16 or lower).
Different settings or bcrypt mark a successful match for rehash rather than
requiring a password reset. A nonparallel test can temporarily lower the cost
with `t.Cleanup(password.SetParamsForTesting(p))`.

Password length rules, user-facing messages, and when to upgrade a hash stay
with the app. Sharing a storage format and a process resource limit does not
require apps to share account policy.

## License

This module is licensed under the [MIT No Attribution license](LICENSE).

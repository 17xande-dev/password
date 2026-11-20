package password

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestSemaphoreCapsHashAndChecks(t *testing.T) {
	t.Cleanup(SetParamsForTesting(cheapParams))
	savedSlots, savedDerive := slots, deriveKey
	t.Cleanup(func() { slots, deriveKey = savedSlots, savedDerive })
	hash, err := Hash(t.Context(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	legacy := makeBcrypt(t, "pw")

	synctest.Test(t, func(t *testing.T) {
		SetConcurrency(0) // A zero setting should still let one caller through.
		s := currentSlots()
		hold := make(chan struct{})
		entered := make(chan string, 12)
		deriveKey = func(password, salt []byte, time, memory uint32, lanes uint8, keyLen uint32) []byte {
			entered <- string(password)
			switch string(password) {
			case "holding":
				<-hold
			case "panic":
				panic("injected KDF panic")
			}
			return savedDerive(password, salt, time, memory, lanes, keyLen)
		}
		defer func() {
			if hold != nil {
				close(hold)
			}
		}()
		go func() { _, _ = Hash(context.Background(), "holding") }()
		synctest.Wait()
		select {
		case <-entered:
		default:
			t.Fatal("Hash did not enter the KDF")
		}

		// Test the public call paths, not just acquire: a path that forgets
		// the semaphore can allocate another 64 MiB during a login burst.
		calls := []struct {
			name string
			run  func(context.Context) error
		}{
			{"Hash", func(ctx context.Context) error { _, err := Hash(ctx, "queued"); return err }},
			{"Check Argon2id", func(ctx context.Context) error { _, _, err := Check(ctx, hash, "pw"); return err }},
			{"Check bcrypt", func(ctx context.Context) error { _, _, err := Check(ctx, legacy, "pw"); return err }},
			{"CheckDummy", func(ctx context.Context) error { _, err := CheckDummy(ctx, "dummy"); return err }},
		}
		for _, call := range calls {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- call.run(ctx) }()
			synctest.Wait()
			select {
			case err := <-done:
				t.Errorf("%s returned with its only slot in use: %v", call.name, err)
				cancel()
				continue
			default:
			}
			cancel()
			synctest.Wait()
			select {
			case err := <-done:
				if !errors.Is(err, ErrBusy) || !errors.Is(err, context.Canceled) {
					t.Errorf("%s: %v, want ErrBusy and context.Canceled", call.name, err)
				}
			default:
				t.Errorf("%s did not return after cancellation", call.name)
			}
			if n := len(s); n != 1 {
				t.Errorf("%s changed occupied slots to %d; want only the holder", call.name, n)
			}
		}
		select {
		case pw := <-entered:
			t.Errorf("%q entered the KDF with the only slot in use", pw)
		default:
		}
		close(hold)
		hold = nil
		synctest.Wait()
		assertEmptySlots(t, s, "holding Hash")

		// Check occupancy before the next call so a lost token is a test
		// failure, not a blocked caller waiting on a permanently full queue.
		for _, call := range calls {
			if err := call.run(t.Context()); err != nil {
				t.Fatalf("%s with a free slot: %v", call.name, err)
			}
			assertEmptySlots(t, s, call.name)
		}
		for _, call := range []struct {
			name string
			run  func()
		}{
			{"Hash", func() { _, _ = Hash(t.Context(), "panic") }},
			{"Check Argon2id", func() { _, _, _ = Check(t.Context(), hash, "panic") }},
			{"CheckDummy", func() { _, _ = CheckDummy(t.Context(), "panic") }},
		} {
			func() {
				defer func() {
					if got := recover(); got != "injected KDF panic" {
						t.Errorf("%s: recovered %v, want injected KDF panic", call.name, got)
					}
					assertEmptySlots(t, s, call.name+" after panic")
				}()
				call.run()
			}()
		}
	})
}

func assertEmptySlots(t *testing.T, s chan struct{}, name string) {
	t.Helper()
	if n := len(s); n != 0 {
		t.Fatalf("%s leaked %d semaphore slot(s)", name, n)
	}
}

func TestSemaphoreReleaseAfterResize(t *testing.T) {
	saved := currentSlots()
	t.Cleanup(func() { slots = saved })

	synctest.Test(t, func(t *testing.T) {
		SetConcurrency(1)
		old := currentSlots()
		release, err := acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		SetConcurrency(4)
		newSlots := currentSlots()
		done := make(chan struct{})
		go func() {
			release()
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
		default:
			// Unblock the worker if release incorrectly targets the new
			// channel, so this regression fails without stranding a goroutine.
			newSlots <- struct{}{}
			t.Fatal("release blocked after resizing the semaphore")
		}
		assertEmptySlots(t, old, "old semaphore")
		assertEmptySlots(t, newSlots, "new semaphore")
	})
}

func TestSemaphoreDeadline(t *testing.T) {
	t.Cleanup(SetParamsForTesting(cheapParams))
	savedSlots := slots
	t.Cleanup(func() { slots = savedSlots })

	synctest.Test(t, func(t *testing.T) {
		SetConcurrency(1)
		slots <- struct{}{}
		defer func() { <-slots }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := Hash(ctx, "pw"); !errors.Is(err, ErrBusy) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Hash: %v, want ErrBusy and context.DeadlineExceeded", err)
		}
	})
	slots = savedSlots

	// Already-ended contexts shouldn't start costly work even with a free slot.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Hash(ctx, "pw"); !errors.Is(err, ErrBusy) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Hash with a free slot: %v, want ErrBusy and context.Canceled", err)
	}
}

func TestDummySpendsOneDerivationAndNeverMatches(t *testing.T) {
	t.Cleanup(SetParamsForTesting(cheapParams))
	saved := deriveKey
	t.Cleanup(func() { deriveKey = saved })
	calls := 0
	deriveKey = func(pw, salt []byte, time, memory uint32, lanes uint8, keyLen uint32) []byte {
		calls++
		got := Params{memory, time, lanes, uint32(len(salt)), keyLen}
		if got != cheapParams {
			t.Errorf("dummy params = %+v, want %+v", got, cheapParams)
		}
		// Even an exact hash match cannot authenticate a nonexistent account.
		return make([]byte, keyLen)
	}
	if ok, err := CheckDummy(t.Context(), "pw"); ok || err != nil || calls != 1 {
		t.Fatalf("CheckDummy = (%t, %v), %d derivations; want (false, nil) and one derivation", ok, err, calls)
	}
}

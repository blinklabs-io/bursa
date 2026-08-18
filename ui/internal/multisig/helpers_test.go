package multisig

import (
	"sync"
)

// memAccounts is an in-memory AccountSource for tests.
//
// The service reads its accounts from the vault now, and the migration reads
// the legacy file with its own reader, so the old JSON store had no production
// caller left. Keeping a whole persistence layer alive to serve tests is how
// dead code survives, so it went and this took its place.
type memAccounts struct {
	mu    sync.Mutex
	accts []Account
}

func (m *memAccounts) List() ([]Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Account, len(m.accts))
	copy(out, m.accts)
	return out, nil
}

func (m *memAccounts) Get(id string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accts {
		if a.ID == id {
			return a, nil
		}
	}
	return Account{}, ErrUnknownAccount
}

func (m *memAccounts) add(a Account) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accts = append(m.accts, a)
}

func (m *memAccounts) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.accts[:0]
	for _, a := range m.accts {
		if a.ID != id {
			kept = append(kept, a)
		}
	}
	m.accts = kept
}

// createForTest composes an account and puts it in the service's source, which
// is what Service.Create did before persistence moved to the vault.
func createForTest(svc *Service, req CreateRequest) (Account, error) {
	acct, err := svc.Compose(req)
	if err != nil {
		return Account{}, err
	}
	svc.accounts.(*memAccounts).add(acct)
	return acct, nil
}

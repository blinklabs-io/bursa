package multisig

import "fmt"

// createForTest composes an account and writes it to whatever source the service
// is reading from.
//
// Service.Create used to do both. Storage moved to the vault (which needs a
// vault password this package has no business holding), so the service composes
// and the caller persists — tests included.
func createForTest(svc *Service, req CreateRequest) (Account, error) {
	acct, err := svc.Compose(req)
	if err != nil {
		return Account{}, err
	}
	st, ok := svc.accounts.(*store)
	if !ok {
		return Account{}, fmt.Errorf("createForTest: unsupported account source %T", svc.accounts)
	}
	if err := st.add(acct); err != nil {
		return Account{}, err
	}
	return acct, nil
}

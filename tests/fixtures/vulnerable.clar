;; A deliberately vulnerable Clarity contract for clarisentry tests.
;; Expected: missing-auth-check, as-contract-tx-sender-auth, unwrap-panic.

(define-data-var owner principal tx-sender)
(define-map balances principal uint)

;; missing-auth-check: writes a data-var with no tx-sender / contract-caller check.
(define-public (set-owner (new-owner principal))
  (begin
    (var-set owner new-owner)
    (ok true)))

;; missing-auth-check: moves STX with no caller check.
(define-public (drain (amount uint) (recipient principal))
  (stx-transfer? amount (as-contract tx-sender) recipient))

;; as-contract-tx-sender-auth: checks tx-sender INSIDE as-contract (== the contract).
(define-public (withdraw (amount uint))
  (as-contract
    (begin
      (asserts! (is-eq tx-sender (var-get owner)) (err u401))
      (stx-transfer? amount tx-sender tx-sender))))

;; unwrap-panic: aborts with no error value.
(define-public (get-balance-or-die (who principal))
  (ok (unwrap-panic (map-get? balances who))))

;; The fixed version — clarisentry should report zero findings.

(define-data-var owner principal tx-sender)
(define-map balances principal uint)

;; guarded with a tx-sender check before the state write.
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u401))
    (var-set owner new-owner)
    (ok true)))

;; caller captured BEFORE as-contract, checked against the owner.
(define-public (withdraw (amount uint))
  (let ((caller tx-sender))
    (asserts! (is-eq caller (var-get owner)) (err u401))
    (as-contract (stx-transfer? amount tx-sender caller))))

;; typed error instead of unwrap-panic.
(define-public (get-balance (who principal))
  (ok (default-to u0 (map-get? balances who))))

;; a genuinely permissionless read-only function — no guard needed, not flagged.
(define-read-only (total-owner)
  (var-get owner))

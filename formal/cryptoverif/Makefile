# =====================================================================
# QASP-Shake CryptoVerif Computational Proofs
# =====================================================================
#
# Targets:
#   all             - Run all proofs
#   secrecy         - Prove session key secrecy + key agreement
#   auth            - Prove mutual authentication (included in secrecy)
#   forward_secrecy - Prove forward secrecy under key compromise
#   clean           - Remove proof logs
#
# Prerequisites:
#   CryptoVerif 2.x (cryptoverif binary in PATH)
#
# Usage:
#   make all
#   make forward_secrecy
#   make clean
# =====================================================================

CV = cryptoverif
CVFLAGS = -lib lib
LOGDIR = logs

.PHONY: all secrecy forward_secrecy clean

all: secrecy forward_secrecy

secrecy: $(LOGDIR)/qasp_shake.log
	@echo "=== QASP-Shake: secrecy + authentication ==="
	@grep "RESULT" $(LOGDIR)/qasp_shake.log || true
	@echo ""

auth: secrecy

forward_secrecy: $(LOGDIR)/qasp_shake_forward_secrecy.log
	@echo "=== QASP-Shake: forward secrecy ==="
	@grep "RESULT" $(LOGDIR)/qasp_shake_forward_secrecy.log || true
	@echo ""

$(LOGDIR)/qasp_shake.log: qasp_shake.ocv lib/hybrid_kem.ocvl lib/mldsa65.ocvl lib/hkdf_sha384.ocvl lib/collision_resistant_hash.ocvl
	@mkdir -p $(LOGDIR)
	$(CV) $(CVFLAGS) qasp_shake.ocv > $(LOGDIR)/qasp_shake.log 2>&1
	@echo "Proof log: $(LOGDIR)/qasp_shake.log"

$(LOGDIR)/qasp_shake_forward_secrecy.log: qasp_shake_forward_secrecy.ocv lib/hybrid_kem.ocvl lib/mldsa65.ocvl lib/hkdf_sha384.ocvl lib/collision_resistant_hash.ocvl
	@mkdir -p $(LOGDIR)
	$(CV) $(CVFLAGS) qasp_shake_forward_secrecy.ocv > $(LOGDIR)/qasp_shake_forward_secrecy.log 2>&1
	@echo "Proof log: $(LOGDIR)/qasp_shake_forward_secrecy.log"

clean:
	rm -rf $(LOGDIR)

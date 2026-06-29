# AEP Sandbox — convenience targets. Run `make help` for the list.
PY ?= python3

.PHONY: help verify attacks ctf init tpm clean

help:
	@echo "AEP Sandbox targets:"
	@echo "  make verify   verify the shipped samples (good -> ALLOW, exceed-scope -> DENY)"
	@echo "  make attacks  run every attack script in attacks/ against the samples"
	@echo "  make ctf      run the CTF judge (did_you_break_it.py)"
	@echo "  make tpm      run the swtpm TPM output-binding demo (needs Docker or swtpm)"
	@echo "  make init     REGENERATE keys + samples (overwrites the shipped fixtures)"
	@echo "  make clean    remove runtime artifacts (attacks/out, state, __pycache__)"

verify:
	$(PY) verify.py samples/good.aep.json
	@echo
	$(PY) verify.py samples/exceed-scope.aep.json || true

attacks:
	@for a in tamper_field forge_rechain forge_full swap_mandate exceed_scope replay strip_sig; do \
		echo "########## $$a ##########"; $(PY) attacks/$$a.py; echo; \
	done

ctf:
	$(PY) did_you_break_it.py

tpm:
	cd tpm-demo && ./demo.sh

init:
	$(PY) mint.py init

clean:
	rm -rf attacks/out state/consumed_nonces.txt
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

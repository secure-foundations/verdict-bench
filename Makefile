PROJECTS = chain parser polyfill rspec_test vest frontend

.PHONY: debug
debug:
	@set -e; \
	for project in $(PROJECTS); do \
		cd $$project; make debug; cd ..; \
	done

.PHONY: release
release:
	@set -e; \
	for project in $(PROJECTS); do \
		cd $$project; make release; cd ..; \
	done

.PHONY: test
test:
	@set -e; \
	for project in $(PROJECTS); do \
		cd $$project; make test; cd ..; \
	done

.PHONY: clean
clean:
	@set -e; \
	for project in $(PROJECTS); do \
		cd $$project; make clean; cd ..; \
	done

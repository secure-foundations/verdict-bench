# In topological order of dependencies
PROJECTS = vest polyfill parser vpl chain test

.PHONY: debug
debug:
	@for project in $(PROJECTS); do \
		cd $$project && make debug && cd ..; \
	done

.PHONY: release
release:
	@for project in $(PROJECTS); do \
		cd $$project && make release && cd ..; \
	done

.PHONY: test
test:
	@for project in $(PROJECTS); do \
		cd $$project && make test && cd ..; \
	done

.PHONY: clean
clean:
	@for project in $(PROJECTS); do \
		cd $$project && make clean && cd ..; \
	done

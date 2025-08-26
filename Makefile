init:
	pip install -r requirements.txt

install:
	pip install --editable .

uninstall:
	pip uninstall pracy

run:
	python -m pracy

doc:
	pdoc pracy # -o ./docs

check:
	mypy --ignore-missing-imports src/pracy/

lint:
	-flake8 .
	-pylint src
	-pylint tests --disable=missing-docstring

format:
	isort ./src
	black ./src
	isort ./tests
	black ./tests

test:
	pytest --cov=pracy --cov=tests

test_relic:
	python ./tools/test_relic_backend.py

export_charm:
	mkdir charm_out
	python ./tools/export_all_to_charm.py

eval:
	python ./tools/parse_relic_benchmark_output.py --file ./eval/bench_relic_out.txt 

clean:
	pyclean .
	-rm -r ./docs
	-rm -r ./.pytest_cache
	-rm -r ./.mypy_cache
	-rm ./.coverage

.PHONY: init install uninstall run doc check lint format test test_relic export_charm clean eval

# Contributing to Talaria

First off, thank you for considering contributing to Talaria! It's people like you that make Talaria such a great tool for the community.

## How Can I Contribute?

### Reporting Bugs
* Check the existing issues to see if the bug has already been reported.
* If not, open a new issue using the **Bug Report** template.
* Include as many details as possible: your OS version, Go version, and the exact command you ran.

### Suggesting Enhancements
* Open a new issue using the **Feature Request** template.
* Describe the current behavior and the behavior you'd like to see.
* Explain why this enhancement would be useful to most Talaria users.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes (`go test ./...`).
4. Format your code with `go fmt`.
5. Open a Pull Request with a clear description of the changes.

## Style Guide
* Follow standard Go idioms and naming conventions.
* Keep modules modular! New scanners should be added to the `scanners/` directory.
* Minimize external dependencies. We prefer native Go standard library implementations for portability.

## Code of Conduct
Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

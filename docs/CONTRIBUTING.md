# Contributing to PVXS

Thank you for your interest in contributing to PVXS! This guide will help you get started.

## How to Contribute

The recommended path for including changes is through [Pull Requests](https://github.com/epics-base/pvxs/pulls).

### Development Workflow

1. **Fork the repository** on GitHub
2. **Clone your fork** and create a feature branch
3. **Make your changes** following the coding guidelines below
4. **Add tests** if applicable
5. **Run the test suite**: `make runtests`
6. **Submit a pull request** with a clear description of your changes

### Reporting Bugs

Before reporting a bug, please check if the issue has already been [reported](https://github.com/epics-base/pvxs/issues).

When reporting a bug, please include:

- EPICS Base version or VCS commit
- PVXS module version or VCS commit
- libevent version (run `pvxget -V` to show these)
- EPICS host and target architectures (e.g., "linux-x86_64")
- Host OS name and version
- Compiler name and version
- The values of any `$EPICS_PVA*` environment variables which are set
- Any local/site modifications to PVXS or libevent
- Concise instructions for reproducing the issue

Additional information which may be relevant:

- Number of network interfaces if more than one
- Whether clients and/or servers are on the same host or different hosts
- Whether clients and/or servers are in the same subnet or different subnets
- Whether network traffic crosses between virtual machines and physical hosts
- Firewall rules on UDP traffic to/from port 5075 or TCP connections to port 5075
- Any local/site modifications to EPICS Base

If the module has built successfully, running `pvxinfo -D` will report much of this information.

See [Bug Reporting Process](../documentation/details.rst#reportbug) for more details.

## Coding Guidelines

### C++ Code Style

When changing C++ code, please:

- **Indent with 4 spaces**. No hard tabs. UNIX style line endings.
- **Try to maintain the style** of surrounding code.
- **Include meaningful code comments** where reasonable.
- **Add doxygen tags** `@since UNRELEASED` when documenting additions/changes to public APIs.

**Do not:**

- Add any C++ global constructors or destructors in the pvxs library. (OK in tools, examples, or tests)

### Commit Guidelines

When committing changes, please:

- **Include a commit message** explaining what and why
- **Break up changes** into multiple commits where reasonable
- **Include whitespace-only changes** as separate commits

Good commit messages:
- Start with a short summary (50 characters or less)
- Include a detailed explanation if needed
- Reference issue numbers if applicable

Example:
```
Fix memory leak in Value array handling

When cloning Value arrays with shared_array, the reference counting
was not properly updated. This fixes the leak by ensuring proper
shared_ptr handling.

Fixes #123
```

## Testing

### Running Tests

Always run the test suite before submitting a pull request:

```bash
make runtests
```

The test suite will verify:
- Unit tests for core functionality
- Integration tests with network operations
- Compatibility with different configurations

### Writing Tests

When adding new features, please include tests:

- Unit tests for new functions/methods
- Integration tests for new functionality
- Regression tests for bug fixes

Test files are located in the `test/` directory.

## Development Setup

### Prerequisites

- EPICS Base >= 3.15.1
- libevent >= 2.0.1 (or build bundled version)
- C++11 compliant compiler
- Git

### Building for Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/pvxs.git
cd pvxs

# Add upstream remote
git remote add upstream https://github.com/epics-base/pvxs.git

# Configure and build
cat <<EOF > configure/RELEASE.local
EPICS_BASE=/path/to/epics-base
EOF

make
```

### Building with Debug Symbols

```bash
# Enable debug build
export EPICS_HOST_ARCH=linux-x86_64-debug
make clean
make
```

## Pull Request Process

1. **Update your fork** with the latest changes from upstream:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** and commit them:
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub

6. **Respond to feedback** and make requested changes

### Pull Request Checklist

Before submitting, ensure:

- [ ] Code follows the coding guidelines
- [ ] Tests pass (`make runtests`)
- [ ] Tests added for new functionality
- [ ] Documentation updated if needed
- [ ] Commit messages are clear
- [ ] No global constructors/destructors in library code
- [ ] Doxygen tags added for public API changes

## Documentation

When adding or modifying features:

- **Update relevant documentation** in the `../documentation/` directory
- **Add examples** if appropriate
- **Update this guide** if the contribution process changes
- **Add release notes** for user-visible changes

## Code Review

All contributions will be reviewed before merging. Please:

- Be responsive to review comments
- Address all feedback
- Keep discussions focused and constructive
- Be patient - reviews may take some time

## Expert APIs

Some APIs are marked as "Expert" APIs and may change incompatibly in minor releases. If you need to use or modify Expert APIs:

- Contact the maintainers first
- Understand that changes may be more disruptive
- Consider proposing promotion to regular API if widely useful

See [Expert APIs documentation](../documentation/details.rst#expertapi) for details.

## Release Policy

PVXS follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Backwards incompatible API changes
- **MINOR**: New features with backwards compatibility, or ABI incompatible changes
- **PATCH**: Bug fixes with backwards compatibility

See [Release Policy](../documentation/details.rst#relpolicy) for details.

## Getting Help

If you have questions about contributing:

- Check existing [GitHub Issues](https://github.com/epics-base/pvxs/issues)
- Search [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/) archives
- Ask questions in a new GitHub issue (tagged as "question")
- Review the [online documentation](https://epics-base.github.io/pvxs/)

## Contributors

Thanks to all who have contributed to PVXS! See the [contributors list](https://github.com/epics-base/pvxs/graphs/contributors).

This project is supported by:
- [ALS-U](https://als.lbl.gov/als-u/overview/) project at [Berkeley Lab](https://www.lbl.gov/)
- [Diamond Light Source](https://www.diamond.ac.uk/)
- [European Spallation Source](https://europeanspallationsource.se/)
- [Fermilab](https://fnal.gov/)
- [SLAC National Accelerator Laboratory](https://www6.slac.stanford.edu/)
- [SNS](https://neutrons.ornl.gov/sns) at [Oak Ridge National Lab](https://www.ornl.gov/)

## Additional Resources

- [Full Contributing Guidelines](../documentation/details.rst#contrib) - Detailed information from RST documentation
- [Bug Reporting Process](../documentation/details.rst#reportbug) - How to report bugs
- [Release Policy](../documentation/details.rst#relpolicy) - Version numbering and release process
- [Expert APIs](../documentation/details.rst#expertapi) - Information about Expert APIs

## Acknowledgments

This contributing guide was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.


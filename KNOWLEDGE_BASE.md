# Knowledge Base - Find Your Port

## Design Documents

### Privacy Policy
- Location: `cache/documents/doc_fc11a89b87b5_08_Privacy_Policy_FindYourPort.md`
- Key Points: [Summary of key privacy commitments]

### Terms of Use
- Location: `cache/documents/doc_88a2264da23f_07_Terms_of_Use_FindYourPort.md`
- Key Points: [Summary of key terms]

### Loop Engineering (Process Definition)
- Location: `cache/documents/doc_7e29cafa1e00_12_Loop_Engineering_FindYourPort.md`
- Key Processes:
  1. **ReAct Loop**: Reasoning → Acting → Observing
  2. **Evaluator-Optimizer**: Continuous improvement cycle
  3. **Human-in-the-Loop**: Validation checkpoints

## Traceability Matrix

| Requirement (PRD/TRD) | Component | Implementation File | Status |
|----------------------|-----------|---------------------|--------|
| App State Management | fyp-core | src/app_state.rs | ✓ Skeleton |
| Port Scanning Engine | fyp-core | src/search_engine.rs | ✓ Skeleton |
| History Logging | fyp-core | src/history_logger.rs | ✓ Skeleton |
| Settings Management | fyp-core | src/settings_manager.rs | ✓ Skeleton |
| OS Abstraction Layer | fyp-os | src/lib.rs, traits.rs | ✓ Skeleton |
| Windows Adapter | fyp-os | src/adapters/windows.rs | ✓ Skeleton |
| Linux Adapter | fyp-os | src/adapters/linux.rs | ✓ Skeleton |
| Main UI Window | fyp-ui | src/app_window.slint | ✓ Skeleton |
| Search Bar Component | fyp-ui | src/components/search_bar.slint | ✓ Skeleton |
| CLI Entry Point | fyp-cli | src/main.rs | ✓ Skeleton |
| CLI Scan Command | fyp-cli | src/commands/scan.rs | ✓ Skeleton |
| CLI History Command | fyp-cli | src/commands/history.rs | ✓ Skeleton |

## Build Instructions (Future)

When Rust toolchain is available:

```bash
# 1. Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Source the environment
source "$HOME/.cargo/env"

# 3. Verify installation
rustc --version
cargo --version

# 4. Build the project
cd find-your-port
cargo build --release

# 5. Run the GUI app
cargo run --release --bin fyp-ui

# 6. Run the CLI app
cargo run --release --bin fyp-cli -- --help
```

## Development Process (Loop Engineering)

Following the ReAct + Evaluator-Optimizer + Human-in-the-Loop pattern:

1. **Goal Definition**: Clear objective for each iteration
2. **Planning**: Break down into actionable tasks
3. **Action**: Implement code/changes
4. **Observation**: Build, test, lint results
5. **Evaluation**: Compare against acceptance criteria
6. **Reflection**: Learn and adjust for next iteration
7. **Loop**: Repeat with refined goals

## Code Quality Standards

- Clippy warnings treated as errors in CI
- Rustfmt enforced via pre-commit hooks
- Comprehensive unit tests for all logic
- Integration tests for critical flows
- Documentation comments for all public APIs

## Release Process

1. Version bump in Cargo.toml files
2. Changelog entry in CHANGELOG.md
3. Git tag creation
4. CI/CD pipeline builds artifacts:
   - Windows: MSI (WiX) and EXE (NSIS)
   - Linux: AppImage, .deb, .rpm
   - macOS: DMG and Homebrew formula
5. Publish to appropriate distribution channels

## Contact & Support

See individual documentation files for specific policies and terms.
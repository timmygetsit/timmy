# Milestone 3: Interactive TUI Polish & Lineage Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform TIMMY's terminal user interface into an interactive, keyboard-driven investigation and management console featuring interactive process lineage trees, multi-process tagging with safety-gated batch termination, enhanced multi-token search filtering, and real-time resource sparkline trends.

**Architecture:** Extend `ratatui` state management in `src/ui/app.rs` with dedicated modals and views. Integrate the native lineage tree generator (`build_session_lineage_tree`, `format_lineage_tree_unicode`) into `SessionInspect` and `ProcessDetail` modals and the Session bottom pane. Implement tagging states (`HashSet<u32>`) with multi-process safety validation (`SafetyShield`) for atomic batch termination. Maintain rolling historical metric ring buffers for interactive sparkline graphs.

**Tech Stack:** Rust 2021, Ratatui 0.29, Crossterm 0.28, SQLite / Rusqlite 0.31, Chrono.

---

### Task 1: Tabbed Session Inspection Modal with Lineage Tree

**Files:**
- Modify: `src/ui/app.rs:38-42, 650-670`
- Modify: `src/ui/views/session_modal.rs:1-120`
- Test: `tests/tui_lineage_modal_tests.rs`

**Step 1: Write the failing test**
Create `tests/tui_lineage_modal_tests.rs` verifying that `SessionInspect` modal contains `LineageTreeNode` data, handles active tab switching (Tree, Cleanup Plan, Raw Resources), and scrolls correctly.

**Step 2: Run test to verify it fails**
Run: `cargo test --test tui_lineage_modal_tests`
Expected: FAIL due to missing fields in `ActiveModal::SessionInspect` and view methods.

**Step 3: Implement minimal code**
1. In `src/ui/app.rs`, update `ActiveModal::SessionInspect` to:
   ```rust
   SessionInspect {
       session: Box<SessionInfo>,
       resources: Vec<TrackedResource>,
       recommendations: Vec<CleanupRecommendation>,
       lineage_tree: Vec<LineageTreeNode>,
       tree_text: String,
       active_tab: usize, // 0: Lineage Tree, 1: Cleanup Plan, 2: Tracked Resources
       scroll: usize,
   }
   ```
2. When triggering `inspect_session` in `src/ui/app.rs`, fetch lineage edges using `orchestrator.get_lineage_edges(&sess.id)`, build the tree via `build_session_lineage_tree`, and format the Unicode tree with `format_lineage_tree_unicode`.
3. In `src/ui/views/session_modal.rs`, render tabs `[1] Lineage Tree  [2] Cleanup Plan  [3] Tracked Resources`, rendering the formatted Unicode tree with scroll support when tab 0 is active.
4. Add key handling in `app.rs` for <kbd>Tab</kbd>, <kbd>1</kbd>-<kbd>3</kbd>, <kbd>↑</kbd>/<kbd>↓</kbd> / <kbd>j</kbd>/<kbd>k</kbd> scroll inside `SessionInspect`.

**Step 4: Run test to verify it passes**
Run: `cargo test --test tui_lineage_modal_tests`
Expected: PASS.

---

### Task 2: Session View Bottom Pane Toggle (Flat Table vs Lineage Tree)

**Files:**
- Modify: `src/ui/app.rs:60-75, 475-535`
- Modify: `src/ui/views/session_view.rs:140-240`
- Test: `tests/tui_session_view_tests.rs`

**Step 1: Write the failing test**
Add test in `tests/tui_session_view_tests.rs` verifying that toggling `show_lineage_tree` switches the bottom pane between tabular resources and rendered tree view.

**Step 2: Run test to verify it fails**
Run: `cargo test --test tui_session_view_tests`
Expected: FAIL due to missing `session_view_show_tree` field on `App`.

**Step 3: Implement minimal code**
1. Add `pub session_view_show_tree: bool` and `pub selected_session_tree: Option<String>` to `App`.
2. When selecting a session, generate and cache its formatted Unicode lineage tree.
3. In `handle_key`, when on `ActiveTab::Sessions`, pressing <kbd>t</kbd> toggles `session_view_show_tree`.
4. In `src/ui/views/session_view.rs`, if `show_lineage_tree` is true, render the tree in the bottom pane block with title `" Process Lineage Tree (press [t] for Table) "`; otherwise render the flat resources table.

**Step 4: Run test to verify it passes**
Run: `cargo test --test tui_session_view_tests`
Expected: PASS.

---

### Task 3: Process View Direct Lineage Tree Jump (<kbd>t</kbd> key)

**Files:**
- Modify: `src/ui/app.rs:520-535, 600-615`
- Test: `tests/tui_process_tree_jump_tests.rs`

**Step 1: Write the failing test**
Add test in `tests/tui_process_tree_jump_tests.rs` ensuring that pressing <kbd>t</kbd> on a process that belongs to an active or historical session immediately opens that session's Lineage Tree modal.

**Step 2: Run test to verify it fails**
Run: `cargo test --test tui_process_tree_jump_tests`
Expected: FAIL.

**Step 3: Implement minimal code**
1. In `src/ui/app.rs`, on `ActiveTab::Processes`, handle KeyCode::Char('t'):
   - Look up selected process.
   - If attributed to an AI agent or associated with a known session, find the session ID (or root agent PID).
   - Open `ActiveModal::SessionInspect` with the Lineage Tree tab active (`active_tab = 0`).
   - If no session exists, display status message `"No session lineage available for this process"`.

**Step 4: Run test to verify it passes**
Run: `cargo test --test tui_process_tree_jump_tests`
Expected: PASS.

---

### Task 4: Multi-Process Tagging & Safety-Gated Batch Termination

**Files:**
- Modify: `src/ui/app.rs:30-70, 410-450, 520-535`
- Modify: `src/ui/views/process_view.rs:30-80`
- Create: `src/ui/views/batch_confirm_modal.rs`
- Modify: `src/ui/views/mod.rs`
- Test: `tests/tui_batch_termination_tests.rs`

**Step 1: Write the failing test**
Create `tests/tui_batch_termination_tests.rs` verifying:
- Tagging processes using <kbd>Space</kbd> adds/removes PIDs from `tagged_pids: HashSet<u32>`.
- Pressing <kbd>x</kbd> with tagged items opens `ActiveModal::ConfirmBatchKill`.
- Processes are audited via `SafetyShield`: system/root processes are segregated as `BLOCKED`, eligible processes as `SAFE`.
- Pressing <kbd>y</kbd> invokes `terminate_process` for each safe PID, skipping blocked PIDs.

**Step 2: Run test to verify it fails**
Run: `cargo test --test tui_batch_termination_tests`
Expected: FAIL due to missing `tagged_pids` and `ConfirmBatchKill`.

**Step 3: Implement minimal code**
1. In `App`, add `pub tagged_pids: std::collections::HashSet<u32>`.
2. In `process_view.rs`, add a `TAG` column showing `[x]` for tagged PIDs and `[ ]` for untagged.
3. In `handle_key`, when on `ActiveTab::Processes`:
   - <kbd>Space</kbd>: toggles the currently selected process's PID in `tagged_pids`.
   - <kbd>a</kbd>: tag all filtered processes (or clear all if all tagged).
4. Update `prompt_termination`:
   - If `tagged_pids` is not empty, collect `Vec<ProcessInfo>` for tagged PIDs.
   - Partition into `eligible` vs `blocked` using `SafetyShield`.
   - Set `modal = ActiveModal::ConfirmBatchKill { processes, blocked, force }`.
5. Create `src/ui/views/batch_confirm_modal.rs` to display the list of processes to terminate, highlighting any protected processes that TIMMY refuses to kill.
6. When user confirms (<kbd>y</kbd>), terminate each eligible process and report counts in `status_message`.

**Step 4: Run test to verify it passes**
Run: `cargo test --test tui_batch_termination_tests`
Expected: PASS.

---

### Task 5: Enhanced Multi-Token Search & Interactive Filter Indicators

**Files:**
- Modify: `src/ui/app.rs:200-290`
- Modify: `src/ui/views/process_view.rs`
- Modify: `src/ui/views/port_view.rs`
- Modify: `src/ui/views/service_view.rs`
- Modify: `src/ui/views/docker_view.rs`
- Modify: `src/ui/views/session_view.rs`
- Test: `tests/tui_filter_tests.rs`

**Step 1: Write the failing test**
Create `tests/tui_filter_tests.rs` testing multi-token search (e.g. query `"claude 3000"` matches a Claude process on port 3000, or `"node 8080"`).

**Step 2: Run test to verify it fails**
Run: `cargo test --test tui_filter_tests`
Expected: FAIL (single substring currently required).

**Step 3: Implement minimal code**
1. Implement `matches_filter(searchable_haystack: &str, query: &str) -> bool` splitting `query` into whitespace-delimited tokens where every token must match case-insensitively (`all(...)`).
2. Apply `matches_filter` across `filtered_processes`, `filtered_ports`, `filtered_services`, `filtered_containers`, and `filtered_sessions`.
3. In each view title, highlight the active filter query in distinct theme color with clear instructions `[Esc] Clear filter`.

**Step 4: Run test to verify it passes**
Run: `cargo test --test tui_filter_tests`
Expected: PASS.

---

### Task 6: Real-Time CPU & Memory Sparkline Trends

**Files:**
- Modify: `src/ui/app.rs:60-95, 120-150, 700-800`
- Test: `tests/tui_sparkline_tests.rs`

**Step 1: Write the failing test**
Create `tests/tui_sparkline_tests.rs` verifying that `App::refresh` records CPU and memory consumption into 30-sample circular history buffers (`cpu_history: Vec<u64>`, `memory_history: Vec<u64>`).

**Step 2: Run test to verify it fails**
Run: `cargo test --test tui_sparkline_tests`
Expected: FAIL.

**Step 3: Implement minimal code**
1. Add `cpu_history: VecDeque<u64>` (0-100% scaled) and `mem_history: VecDeque<u64>` (MB scaled) with max capacity 40 to `App`.
2. In `App::refresh()`, push `snapshot.metrics.total_agent_cpu_usage` and `snapshot.metrics.total_agent_memory_bytes / (1024 * 1024)`.
3. In `src/ui/app.rs` rendering the top header dashboard, add two compact `Sparkline` widgets displaying AI Agent CPU Trend and AI Agent Memory Trend.

**Step 4: Run test to verify it passes**
Run: `cargo test --test tui_sparkline_tests`
Expected: PASS.

---

### Task 7: Quality Gates & Verification

**Steps:**
1. Run `cargo check` and `cargo test --all-targets --all-features`.
2. Run `cargo fmt --check`.
3. Run `cargo clippy --all-targets --all-features -- -D warnings`.
4. Run cross-compilation check: `cargo check --target x86_64-apple-darwin --all-targets --all-features`.
5. Update `ROADMAP.md` and `README.md` to reflect Milestone 3 features.

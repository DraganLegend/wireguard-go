# AGENTS.md Specification v2.0

## 1. Overview

This file provides instructions, constraints, and verification procedures for AI agents operating within this project. Its purpose is to ensure that AI-generated contributions align with the project's standards, architecture, and conventions. All agents MUST read and adhere to the specifications in any `AGENTS.md` file relevant to their tasks.

## 2. Core Principles

### 2.1. Scope
An `AGENTS.md` file's scope is the directory it resides in and all its subdirectories. More deeply-nested `AGENTS.md` files can override instructions from parent directories.

### 2.2. Precedence
The order of precedence for instructions is as follows, from highest to lowest:
1.  **Direct Instructions:** Instructions given directly in the prompt from the user/developer.
2.  **Nested `AGENTS.md`:** The `AGENTS.md` file closest to the modified file.
3.  **Parent `AGENTS.md`:** `AGENTS.md` files in parent directories.
4.  **Agent's General Knowledge:** The agent's pre-existing training data and general knowledge.

### 2.3. Verification
Successful completion of a task is contingent on passing all specified verification steps. If verification steps are defined, you MUST execute them and confirm they pass *after* all changes are made.

## 3. Recommended Structure

`AGENTS.md` files should be structured with the following sections for clarity.

### 3.1. `## Project Context`
(Optional, but recommended) Briefly describe the purpose of the code within this scope. What are its primary responsibilities? Who are its users? This helps the agent make better high-level decisions.

### 3.2. `## Coding Style & Conventions`
Detail specific coding style rules. Whenever possible, provide clear "Do" and "Don't" examples. This is more effective than just describing the rule.

### 3.3. `## Architectural Constraints`
Define rules about the system's architecture. This is critical for maintaining project integrity.
- **Dependencies:** Rules for adding, updating, or using third-party libraries.
- **Module Interaction:** How modules within this scope can or cannot interact with others.
- **Forbidden Patterns:** Any anti-patterns that must be avoided (e.g., global state, circular dependencies).

### 3.4. `## PR / Commit Message Format`
Specify the exact format for Pull Request titles, bodies, and commit messages. Reference standards like [Conventional Commits](https://www.conventionalcommits.org/) if applicable.

### 3.5. `## Verification Steps`
**This is a mandatory section if checks are required.** Provide a list of exact, runnable commands that the agent MUST execute to verify its work. The agent must report the exit codes or output of these commands as proof of success.

---

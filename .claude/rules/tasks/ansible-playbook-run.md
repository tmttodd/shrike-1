---
description: Task — Write and execute an Ansible playbook for host configuration
globs:
  - "**/*"
---

# Task: Ansible Playbook Run

**Agent**: Changemaker
**Trigger**: When host-level configuration changes are needed (sysctl, systemd, packages, NFS)
**Risk Level**: AUTO (write playbook), NOTIFY (dry-run), APPROVE (execute)
**Estimated Duration**: 10-30 minutes

## Prerequisites

- Ansible installed on Mac (`brew install ansible` or `pip install ansible`)
- SSH key access to target hosts
- Inventory file at `~/Documents/Claude/ansible/inventory/hosts.yml`
- See `CLAUDE.md` Authority & Access section for host access guidance

## Procedure

### Step 1: Write or modify the playbook

```bash
# All playbooks live in:
~/Documents/Claude/ansible/playbooks/

# Use existing inventory:
~/Documents/Claude/ansible/inventory/hosts.yml
```

Playbook requirements:
- Must be **idempotent** (safe to run multiple times)
- Must include `check_mode` support
- Must have descriptive task names
- Must tag tasks for selective execution

### Step 2: Dry-run (--check mode)

```bash
cd ~/Documents/Claude/ansible
ansible-playbook playbooks/<playbook>.yml --check --diff -i inventory/hosts.yml
```

Review output. If changes look correct, proceed to Step 3.
**Autonomy**: NOTIFY — tell Todd what the dry-run showed.

### Step 3: Execute (requires APPROVE for first run per playbook)

```bash
ansible-playbook playbooks/<playbook>.yml --diff -i inventory/hosts.yml
```

**Autonomy**: APPROVE for first run of any playbook.
After first successful run: NOTIFY for subsequent executions of the same playbook.

### Step 4: Verify changes

```bash
ansible-playbook playbooks/<playbook>.yml --check -i inventory/hosts.yml
# Should show 0 changes if playbook is idempotent
```

## Example Inventory (`~/Documents/Claude/ansible/inventory/hosts.yml`)

```yaml
all:
  children:
    docker_hosts:
      hosts:
        tmtdockp01:
          ansible_host: 192.168.20.15
          ansible_user: tmiller
          ansible_become: true
        tmtdockp02:
          ansible_host: 192.168.20.16
          ansible_user: tmiller
          ansible_become: true
    storage:
      hosts:
        tmtfnp01:
          ansible_host: 192.168.20.14
          ansible_user: tmiller
          ansible_become: true
```

## Failure Handling

- If playbook fails: review error, fix playbook, re-run `--check`
- If host unreachable: check SSH, report to Sentinel
- If changes cause issues: run rollback tasks (every playbook should have them)

## Report

Write to: `reports/YYYY-MM-DD-changemaker-change-summary.md`

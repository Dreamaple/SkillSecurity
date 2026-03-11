"""Quick performance benchmark for QA validation."""

import statistics
import time

from skillsecurity import SkillGuard

guard = SkillGuard()

tests = [
    {"tool": "shell", "command": "ls /tmp"},
    {"tool": "shell", "command": "rm -rf /"},
    {"tool": "file.read", "path": "/home/user/.ssh/id_rsa"},
    {
        "tool": "network.request",
        "url": "https://api.stripe.com/v1/charges",
        "method": "POST",
        "body": {"amount": 4999},
    },
    {
        "tool": "network.request",
        "url": "https://unknown.com/api",
        "method": "POST",
        "body": '{"messages": [{"role": "user", "content": "secret"}]}',
    },
    {"tool": "file.write", "path": "/etc/passwd"},
    {"tool": "shell", "command": "echo hello"},
    {"tool": "network.request", "url": "https://api.github.com/repos", "method": "GET"},
    {"tool": "file.read", "path": "/home/user/project/readme.md"},
    {"tool": "shell", "command": "python main.py"},
]

# Warmup
for t in tests:
    guard.check(t)

# Benchmark
times = []
for _ in range(1000):
    for t in tests:
        start = time.perf_counter()
        guard.check(t)
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)

print(f"Total calls: {len(times)}")
print(f"Mean:   {statistics.mean(times):.3f} ms")
print(f"Median: {statistics.median(times):.3f} ms")
print(f"P95:    {sorted(times)[int(len(times) * 0.95)]:.3f} ms")
print(f"P99:    {sorted(times)[int(len(times) * 0.99)]:.3f} ms")
print(f"Max:    {max(times):.3f} ms")
print(f"Min:    {min(times):.3f} ms")

# Per-test-case results
print("\nPer-case breakdown:")
for i, t in enumerate(tests):
    case_times = times[i :: len(tests)]
    action_str = guard.check(t).action.value
    desc = t.get("command", t.get("path", t.get("url", "?")))
    print(
        f"  [{action_str:5s}] {desc[:50]:50s} "
        f"mean={statistics.mean(case_times):.3f}ms "
        f"p99={sorted(case_times)[int(len(case_times) * 0.99)]:.3f}ms"
    )

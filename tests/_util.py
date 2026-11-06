import os, random, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
SEED = int(os.environ.get("AST_TEST_SEED") or random.SystemRandom().randrange(1 << 30))
FUZZ_N = int(os.environ.get("AST_FUZZ_N", "2000"))
print("AST_TEST_SEED=%d AST_FUZZ_N=%d" % (SEED, FUZZ_N), file=sys.stderr)

BASE_POLICY = {
    "schema_version": 1, "arbitrary_shell": False, "approval_ttl_seconds": 300,
    "tools": {"docs.read": {"risk": "low", "path_arg": "path"},
              "docs.write": {"risk": "medium", "requires_approval": True, "path_arg": "path"},
              "mail.send_draft": {"risk": "high"}},
    "agents": {"agent-a": {"allowed_tools": ["docs.read", "docs.write", "mail.send_draft"],
                           "allowed_paths": ["ws/docs/**"]},
               "agent-b": {"allowed_tools": ["docs.read"], "allowed_paths": ["ws/docs/*.txt"]}},
    "approvers": ["human-1"],
}

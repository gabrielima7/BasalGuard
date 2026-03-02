import time
import timeit
from collections.abc import Sequence

# We will test the old vs new implementation for membership checking.

# Old implementation style
def old_style(allowed_commands: Sequence[str] | None = None):
    # Get command whitelist
    if allowed_commands is not None:
        whitelist = list(allowed_commands)
    else:
        whitelist = list(DEFAULT_ALLOWED_COMMANDS)
    return whitelist

# New implementation style
def new_style(allowed_commands: Sequence[str] | None = None):
    # Get command whitelist
    if allowed_commands is not None:
        whitelist = allowed_commands
    else:
        whitelist = DEFAULT_ALLOWED_COMMANDS
    return whitelist

# Setup
DEFAULT_ALLOWED_COMMANDS = frozenset(
    {
        "python", "python3", "pip", "pip3", "poetry", "pipx",
        "git", "make", "pytest", "mypy", "ruff", "bandit", "safety",
        "semgrep", "pre-commit", "echo", "cat", "ls", "pwd", "mkdir",
        "rm", "cp", "mv", "touch", "chmod", "which",
    }
)

def benchmark():
    # Test with default commands (None passed)
    print("Testing with default commands (None passed):")
    old_time_none = timeit.timeit(lambda: old_style(None), number=100000)
    new_time_none = timeit.timeit(lambda: new_style(None), number=100000)

    print(f"Old style: {old_time_none:.6f} seconds")
    print(f"New style: {new_time_none:.6f} seconds")
    print(f"Improvement: {(old_time_none - new_time_none) / old_time_none * 100:.2f}%\n")

    # Test with a provided list
    custom_list = ["python", "pip"]
    print("Testing with custom list:")
    old_time_list = timeit.timeit(lambda: old_style(custom_list), number=100000)
    new_time_list = timeit.timeit(lambda: new_style(custom_list), number=100000)

    print(f"Old style: {old_time_list:.6f} seconds")
    print(f"New style: {new_time_list:.6f} seconds")
    print(f"Improvement: {(old_time_list - new_time_list) / old_time_list * 100:.2f}%\n")

    # Test with a provided set/frozenset
    custom_set = frozenset({"python", "pip"})
    print("Testing with custom frozenset:")
    old_time_set = timeit.timeit(lambda: old_style(custom_set), number=100000)
    new_time_set = timeit.timeit(lambda: new_style(custom_set), number=100000)

    print(f"Old style: {old_time_set:.6f} seconds")
    print(f"New style: {new_time_set:.6f} seconds")
    print(f"Improvement: {(old_time_set - new_time_set) / old_time_set * 100:.2f}%\n")


if __name__ == "__main__":
    benchmark()

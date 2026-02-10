"""Main module for app."""

import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def greet(name: str) -> str:
    """
    Return a greeting message.

    Args:
        name: The name to greet.

    Returns:
        A greeting message.

    """
    return f"Hello, {name}!"


def main() -> None:
    """Run the main entry point for the application."""
    message = greet("World")
    logger.info(message)


if __name__ == "__main__":
    main()

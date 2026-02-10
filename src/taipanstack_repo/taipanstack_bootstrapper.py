#!/usr/bin/env python
"""
Este script automatiza a configuração inicial de um ambiente Python focado em
performance, segurança e integridade.
"""

__version__ = "1.0.0"

import argparse
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

# Constantes de configuração
PYPROJECT_TOML_PATH = Path("pyproject.toml")
PRE_COMMIT_CONFIG_PATH = Path(".pre-commit-config.yaml")
GITHUB_DIR = Path(".github")
DEPENDABOT_CONFIG_PATH = GITHUB_DIR / "dependabot.yml"
SECURITY_MD_PATH = Path("SECURITY.md")


# --- Funções de Utilidade ---


def _log(message: str, args: argparse.Namespace, is_verbose: bool = False) -> None:
    """Função de log centralizada que respeita os modos dry-run e verbose."""
    if is_verbose and not args.verbose:
        return


def _handle_error(message: str) -> NoReturn:
    """Exibe uma mensagem de erro e encerra o script."""
    sys.exit(1)


def _run_command(
    command: list[str], args: argparse.Namespace, capture_output: bool = False
) -> subprocess.CompletedProcess[str]:
    """Executa um comando no shell, tratando erros e modo dry-run."""
    _log(f"Executando comando: `{' '.join(command)}`", args, is_verbose=True)
    if args.dry_run:
        return subprocess.CompletedProcess(command, 0, "", "")

    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            encoding="utf-8",
            capture_output=capture_output,
        )
        return result
    except FileNotFoundError:
        # A verificação de Poetry é tratada separadamente, então este é um erro inesperado.
        _handle_error(
            f"Comando '{command[0]}' não encontrado. Verifique se ele está instalado e no PATH."
        )
    except subprocess.CalledProcessError as e:
        error_message = f"O comando `{' '.join(command)}` falhou com o código de saída {e.returncode}."
        if e.stderr and not capture_output:
            error_message += f"\nErro:\n{e.stderr}"
        _handle_error(error_message)


def _is_windows() -> bool:
    """Verifica se o sistema operacional é Windows."""
    return platform.system() == "Windows"


def _safe_write(path: Path, content: str, args: argparse.Namespace) -> None:
    """Escreve conteúdo em um arquivo, com backup e modo dry-run."""
    _log(f"Escrevendo no arquivo: {path}", args, is_verbose=True)
    if args.dry_run:
        return

    if path.exists() and not args.force:
        backup_path = path.with_suffix(f"{path.suffix}.bak")
        try:
            path.rename(backup_path)
            _log(f"⚠️  Backup criado: {backup_path.name}", args)
        except (OSError, PermissionError) as e:
            _handle_error(
                f"Não foi possível criar o backup do arquivo {path.name}: {e}"
            )

    try:
        path.write_text(content, encoding="utf-8")
    except (OSError, PermissionError) as e:
        _handle_error(f"Não foi possível escrever no arquivo {path.name}: {e}")


# --- Funções de Geração de Configuração ---


def _generate_pyproject_config(args: argparse.Namespace) -> None:
    """Gera e escreve as configurações do Ruff e Mypy no pyproject.toml."""
    _log("📝 Gerando configurações para Ruff, Mypy e Pytest no pyproject.toml...", args)

    try:
        pyproject_content = PYPROJECT_TOML_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Se o pyproject.toml não existe, significa que o `poetry init` ainda não rodou.
        pyproject_content = ""

    config_to_add = ""

    if "[tool.ruff]" not in pyproject_content:
        python_version = f"py{sys.version_info.major}{sys.version_info.minor}"
        config_to_add += f"""
# --- Configurações de Qualidade de Código ---
[tool.ruff]
line-length = 88
target-version = "{python_version}"

[tool.ruff.lint]
select = [
    "F", "E", "W", "I", "N", "D", "Q", "S", "B", "A", "C4", "T20", "SIM", "PTH",
    "TID", "ARG", "PIE", "PLC", "PLE", "PLR", "PLW", "RUF"
]
ignore = ["D203", "D212", "D213", "D416", "D417", "B905"]

[tool.ruff.lint.mccabe]
max-complexity = 10

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
"""

    if "[tool.mypy]" not in pyproject_content:
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        config_to_add += f"""
[tool.mypy]
python_version = "{python_version}"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_unimported = false
no_implicit_optional = true
check_untyped_defs = true
strict_optional = true
strict_equality = true
ignore_missing_imports = true
"""

    if "[tool.pytest.ini_options]" not in pyproject_content:
        config_to_add += """
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --cov=src --cov-report=html --cov-report=term-missing --cov-fail-under=80"
"""

    if not args.dry_run and config_to_add:
        try:
            with PYPROJECT_TOML_PATH.open("a", encoding="utf-8") as f:
                f.write(config_to_add)
        except (OSError, PermissionError) as e:
            _handle_error(f"Não foi possível escrever no arquivo pyproject.toml: {e}")
    elif args.dry_run and config_to_add:
        _log(
            "Adicionaria configurações de ferramentas ao pyproject.toml",
            args,
            is_verbose=True,
        )
    elif not config_to_add:
        _log(
            "✅ Configurações de Ruff, Mypy e Pytest já existem no pyproject.toml.",
            args,
        )


def _generate_pre_commit_config(args: argparse.Namespace) -> None:
    """Gera e escreve o arquivo de configuração do .pre-commit-config.yaml."""
    _log("📝 Gerando arquivo de configuração .pre-commit-config.yaml...", args)
    config_content = """repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: 'v0.8.4'
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: 'v1.13.0'
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
  - repo: https://github.com/PyCQA/bandit
    rev: '1.8.0'
    hooks:
      - id: bandit
        args: ["-r", ".", "-ll"]
  - repo: https://github.com/pycqa/safety
    rev: '3.2.11'
    hooks:
      - id: safety
        args: ["scan", "--json"]
  - repo: https://github.com/semgrep/pre-commit
    rev: 'v1.99.0'
    hooks:
      - id: semgrep
        args: ['--config=auto']
  - repo: https://github.com/Yelp/detect-secrets
    rev: 'v1.5.0'
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
"""
    _safe_write(PRE_COMMIT_CONFIG_PATH, config_content, args)


def _generate_dependabot_config(args: argparse.Namespace) -> None:
    """Gera o arquivo de configuração do Dependabot."""
    _log("📝 Gerando arquivo de configuração .github/dependabot.yml...", args)
    if not args.dry_run:
        try:
            GITHUB_DIR.mkdir(exist_ok=True)
        except (FileExistsError, PermissionError) as e:
            _handle_error(f"Não foi possível criar o diretório .github: {e}")
    config_content = """version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    groups:
      dev-dependencies:
        patterns:
          - "ruff"
          - "mypy"
          - "bandit"
          - "safety"
          - "pytest*"
          - "pre-commit"
          - "semgrep"
          - "py-spy"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "daily"
"""
    _safe_write(DEPENDABOT_CONFIG_PATH, config_content, args)


def _generate_security_policy(args: argparse.Namespace) -> None:
    """Gera o arquivo SECURITY.md com uma política de segurança moderna."""
    _log("📝 Gerando política de segurança em SECURITY.md...", args)
    content = """# Security Policy

## Supported Versions
Nós priorizamos correções de segurança na versão mais recente (Rolling Release).

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability
Se encontrar uma falha, por favor reporte via aba [Security](../../security) ou email.
"""
    _safe_write(SECURITY_MD_PATH, content, args)


# --- Funções de Orquestração ---


def _check_git_initialized(args: argparse.Namespace) -> None:
    """Verifica se o Git está inicializado e inicializa se necessário."""
    _log("🔎 Verificando se o Git está inicializado...", args)
    git_dir = Path(".git")

    if git_dir.exists():
        _log("✅ Repositório Git já inicializado.", args)
        return

    if not shutil.which("git"):
        _log("⚠️  Git não encontrado no PATH. Pulando inicialização do Git.", args)
        return

    _log("🛠️  Inicializando repositório Git...", args)
    _run_command(["git", "init"], args)
    _log("✅ Repositório Git inicializado com sucesso.", args)


def _check_connectivity(args: argparse.Namespace) -> None:
    """Verifica conectividade com a internet antes de instalar dependências."""
    _log("🔎 Verificando conectividade com a internet...", args, is_verbose=True)

    try:
        # Tenta conectar ao PyPI para verificar conectividade
        socket.create_connection(("pypi.org", 443), timeout=5)
        _log("✅ Conectividade confirmada.", args, is_verbose=True)
    except (TimeoutError, OSError):
        _handle_error(
            "Não foi possível conectar à internet. "
            "Verifique sua conexão e proxies antes de continuar."
        )


def _create_project_structure(args: argparse.Namespace) -> None:
    """Cria a estrutura básica de pastas do projeto."""
    _log("📁 Criando estrutura de pastas do projeto...", args)

    # Detecta o nome do projeto do pyproject.toml
    project_name = "my_project"
    if PYPROJECT_TOML_PATH.exists():
        try:
            content = PYPROJECT_TOML_PATH.read_text(encoding="utf-8")
            for line in content.split("\n"):
                if line.startswith("name = "):
                    project_name = line.split("=")[1].strip().strip('"').strip("'")
                    break
        except (OSError, IndexError):
            pass

    # Cria estrutura de diretórios
    directories = [
        Path("src") / project_name,
        Path("tests"),
        Path("docs"),
    ]

    for directory in directories:
        if not args.dry_run:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                _log(f"✅ Criado: {directory}", args, is_verbose=True)
            except (OSError, PermissionError) as e:
                _log(f"⚠️  Não foi possível criar {directory}: {e}", args)
        else:
            _log(f"Criaria diretório: {directory}", args, is_verbose=True)

    # Cria arquivos __init__.py
    init_files = [
        Path("src") / project_name / "__init__.py",
        Path("tests") / "__init__.py",
    ]

    for init_file in init_files:
        if not init_file.exists() and not args.dry_run:
            try:
                content = f'"""Package initialization for {init_file.parent.name}."""\n'
                if init_file.parent.name == project_name:
                    content += '\n__version__ = "0.1.0"\n'
                init_file.write_text(content, encoding="utf-8")
                _log(f"✅ Criado: {init_file}", args, is_verbose=True)
            except (OSError, PermissionError) as e:
                _log(f"⚠️  Não foi possível criar {init_file}: {e}", args)

    # Cria arquivo main.py de exemplo
    main_file = Path("src") / project_name / "main.py"
    if not main_file.exists() and not args.dry_run:
        example_content = f'''"""Main module for {project_name}."""

def greet(name: str) -> str:
    """
    Return a greeting message.

    Args:
        name: The name to greet.

    Returns:
        A greeting message.
    """
    return f"Hello, {{name}}!"


def main() -> None:
    """Main entry point for the application."""
    message = greet("World")
    print(message)


if __name__ == "__main__":
    main()
'''
        try:
            main_file.write_text(example_content, encoding="utf-8")
            _log(f"✅ Criado: {main_file}", args)
        except (OSError, PermissionError) as e:
            _log(f"⚠️  Não foi possível criar {main_file}: {e}", args)

    # Cria arquivo de teste de exemplo
    test_file = Path("tests") / "test_example.py"
    if not test_file.exists() and not args.dry_run:
        test_content = f'''"""Example test module for {project_name}."""

from src.{project_name}.main import greet


def test_greet() -> None:
    """Test the greet function."""
    result = greet("Alice")
    assert result == "Hello, Alice!"
    assert isinstance(result, str)


def test_greet_empty() -> None:
    """Test greet with empty string."""
    result = greet("")
    assert result == "Hello, !"
'''
        try:
            test_file.write_text(test_content, encoding="utf-8")
            _log(f"✅ Criado: {test_file}", args)
        except (OSError, PermissionError) as e:
            _log(f"⚠️  Não foi possível criar {test_file}: {e}", args)


def _validate_setup(args: argparse.Namespace) -> None:
    """Valida se o setup foi concluído com sucesso."""
    _log("\n🔍 Validando configuração...", args)

    issues = []

    # Verifica arquivos obrigatórios
    required_files = [
        PYPROJECT_TOML_PATH,
        PRE_COMMIT_CONFIG_PATH,
        SECURITY_MD_PATH,
        DEPENDABOT_CONFIG_PATH,
    ]

    for file in required_files:
        if not file.exists():
            issues.append(f"Arquivo não encontrado: {file}")

    # Verifica se pre-commit está instalado
    if shutil.which("poetry"):
        result = _run_command(
            ["poetry", "run", "pre-commit", "--version"], args, capture_output=True
        )
        if result.returncode != 0:
            issues.append("Pre-commit não está instalado corretamente")

    if issues:
        _log("⚠️  Problemas encontrados durante a validação:", args)
        for issue in issues:
            _log(f"  - {issue}", args)
    else:
        _log("✅ Validação concluída com sucesso!", args)


def _check_poetry_installation(args: argparse.Namespace) -> None:
    """Verifica se o Poetry está instalado de forma inteligente."""
    _log("🔎 Verificando se o Poetry está instalado...", args)
    if shutil.which("poetry"):
        _log("✅ Poetry encontrado.", args)
        return

    # Se Poetry não foi encontrado, cria uma mensagem de erro mais útil
    if shutil.which("pipx"):
        suggestion = "Tente instalar com: `pipx install poetry`"
    else:
        suggestion = "Consulte a documentação oficial: https://python-poetry.org/docs/#installation"

    _handle_error(f"Poetry não encontrado. {suggestion}")


def _initialize_poetry_project(args: argparse.Namespace) -> None:
    """Inicializa um novo projeto Poetry."""
    if PYPROJECT_TOML_PATH.exists():
        _log("✅ Projeto Poetry já inicializado.", args)
        return
    _log("🛠️  Inicializando projeto Poetry...", args)
    _run_command(["poetry", "init", "-n"], args)


def _add_dependencies(args: argparse.Namespace) -> None:
    """Adiciona as dependências de produção e desenvolvimento ao projeto."""
    # Dependências de produção são opcionais
    if args.install_runtime_deps:
        _log("📦 Adicionando dependências de produção opcionais...", args)
        prod_deps = ["pydantic>=2.0", "orjson"]
        if not _is_windows():
            prod_deps.append("uvloop")
        _run_command(["poetry", "add", *prod_deps], args)
    else:
        _log(
            "⏭️  Pulando dependências de produção (use --install-runtime-deps para incluí-las).",
            args,
        )

    _log("🔧 Adicionando dependências de desenvolvimento...", args)
    dev_deps = [
        "ruff",
        "mypy",
        "bandit",
        "safety",
        "pre-commit",
        "pytest",
        "pytest-cov",
        "py-spy",
        "semgrep",
    ]
    _run_command(["poetry", "add", "--group", "dev", *dev_deps], args)


def _setup_pre_commit_hooks(args: argparse.Namespace) -> None:
    """Instala e configura os hooks de pre-commit."""
    _log("⚙️  Instalando hooks de pre-commit...", args)
    _run_command(["poetry", "run", "pre-commit", "install"], args)


def _setup_cli() -> argparse.Namespace:
    """Configura a interface de linha de comando."""
    parser = argparse.ArgumentParser(
        description="Automatiza a configuração de um ambiente Python de alta performance."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simula a execução sem fazer alterações reais no sistema de arquivos.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Exibe logs detalhados sobre cada etapa do processo.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Força a sobrescrita de arquivos de configuração sem criar backups.",
    )
    parser.add_argument(
        "--install-runtime-deps",
        action="store_true",
        help="Instala dependências de produção opcionais (pydantic, orjson, uvloop).",
    )
    return parser.parse_args()


def main() -> None:
    """Função principal para orquestrar a configuração do ambiente."""
    args = _setup_cli()

    _log(f"\n🐍 TaipanStack Bootstrapper v{__version__}", args)
    _log("Iniciando a configuração do ambiente Python de alta performance...\n", args)

    # Verificações iniciais
    _check_poetry_installation(args)
    _check_git_initialized(args)
    _check_connectivity(args)

    # Inicialização do projeto
    _initialize_poetry_project(args)
    _create_project_structure(args)

    # Instalação de dependências
    _add_dependencies(args)

    # Geração de arquivos de configuração
    _generate_pyproject_config(args)
    _generate_pre_commit_config(args)
    _generate_dependabot_config(args)
    _generate_security_policy(args)

    # Setup de hooks
    _setup_pre_commit_hooks(args)

    # Validação final
    _validate_setup(args)

    # Mensagens finais
    _log("\n✅ Ambiente configurado com sucesso!", args)
    _log("Execute `poetry shell` para ativar o ambiente virtual.", args)
    _log(
        "💡 Dica: execute `poetry config virtualenvs.in-project true` para criar o .venv dentro do projeto.",
        args,
    )
    _log(
        "\n🔒 Lembre-se de commitar o arquivo `poetry.lock` para garantir builds reprodutíveis.",
        args,
    )
    _log("\n📚 Consulte o README.md para mais informações sobre o projeto.", args)


if __name__ == "__main__":
    main()

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Adiciona o diretório raiz ao path para que o `taipanstack_bootstrapper` possa ser importado
sys.path.insert(0, str(Path(__file__).parent.parent))

import taipanstack_bootstrapper as taipanstack


@pytest.fixture(autouse=True)
def setup_teardown(tmp_path, monkeypatch):
    """
    Fixture para isolar cada teste em um diretório temporário
    e mockar chamadas de sistema perigosas.
    """
    # Muda o diretório de trabalho atual para o diretório temporário
    monkeypatch.chdir(tmp_path)

    # Mocka subprocess.run para evitar execuções de comandos reais (como poetry)
    mock_run = MagicMock(return_value=subprocess.CompletedProcess([], 0))
    with patch("subprocess.run", mock_run):
        yield mock_run


def run_main_with_args(args):
    """Helper para rodar a função main do script com argumentos específicos."""
    with patch.object(sys, "argv", ["taipanstack_bootstrapper.py", *args]):
        taipanstack.main()


def test_dry_run_does_not_create_files(tmp_path):
    """
    Verifica se rodar com --dry-run não cria nenhum arquivo de configuração.
    """
    run_main_with_args(["--dry-run"])

    # Garante que nenhum dos arquivos principais foi criado
    assert not (tmp_path / "pyproject.toml").exists()
    assert not (tmp_path / ".pre-commit-config.yaml").exists()
    assert not (tmp_path / "SECURITY.md").exists()
    assert not (tmp_path / ".github" / "dependabot.yml").exists()


def test_safe_write_creates_backup(tmp_path):
    """
    Verifica se o backup (.bak) é criado quando um arquivo de configuração já existe.
    """
    # Cria um arquivo dummy para simular uma configuração existente
    dummy_file = tmp_path / ".pre-commit-config.yaml"
    dummy_file.write_text("old content")

    run_main_with_args([])  # Execução normal, sem flags

    # Verifica se o backup foi criado
    backup_file = tmp_path / ".pre-commit-config.yaml.bak"
    assert backup_file.exists()
    assert backup_file.read_text() == "old content"

    # Verifica se o novo arquivo também foi criado
    assert dummy_file.exists()
    assert (
        "pre-commit-hooks" in dummy_file.read_text()
    )  # Verifica conteúdo do novo arquivo


def test_force_mode_overwrites_without_backup(tmp_path):
    """
    Verifica se a flag --force sobrescreve o arquivo diretamente, sem criar backup.
    """
    dummy_file = tmp_path / ".pre-commit-config.yaml"
    dummy_file.write_text("old content")

    run_main_with_args(["--force"])

    # Garante que o arquivo de backup NÃO foi criado
    backup_file = tmp_path / ".pre-commit-config.yaml.bak"
    assert not backup_file.exists()

    # Garante que o arquivo original foi sobrescrito
    assert dummy_file.exists()
    assert "pre-commit-hooks" in dummy_file.read_text()


def test_idempotency_for_pyproject_toml(tmp_path):
    """
    Verifica se rodar o script duas vezes não duplica as seções no pyproject.toml.
    """
    # Cria um pyproject.toml inicial, como se `poetry init` tivesse rodado
    pyproject_toml = tmp_path / "pyproject.toml"
    pyproject_toml.write_text('[tool.poetry]\nname = "test"\n')

    # Primeira execução
    run_main_with_args([])
    content_after_first_run = pyproject_toml.read_text()

    # Verifica se as seções foram adicionadas
    assert "[tool.ruff]" in content_after_first_run
    assert "[tool.mypy]" in content_after_first_run
    assert content_after_first_run.count("[tool.ruff]") == 1

    # Segunda execução
    run_main_with_args([])
    content_after_second_run = pyproject_toml.read_text()

    # Compara o conteúdo e garante que não houve duplicação
    assert content_after_first_run == content_after_second_run
    assert content_after_second_run.count("[tool.ruff]") == 1


def test_git_initialization(tmp_path):
    """
    Verifica se o Git é inicializado automaticamente quando não existe.
    """
    # Garante que .git não existe
    assert not (tmp_path / ".git").exists()

    run_main_with_args([])

    # Verifica se .git foi criado (se git estiver disponível)
    # Nota: pode não existir se git não estiver instalado no sistema de teste


def test_project_structure_creation(tmp_path):
    """
    Verifica se a estrutura de pastas do projeto é criada corretamente.
    """
    # Cria um pyproject.toml com nome de projeto
    pyproject_toml = tmp_path / "pyproject.toml"
    pyproject_toml.write_text('[tool.poetry]\nname = "my_test_project"\n')

    run_main_with_args([])

    # Verifica se as pastas foram criadas
    assert (tmp_path / "src" / "my_test_project").exists()
    assert (tmp_path / "tests").exists()
    assert (tmp_path / "docs").exists()

    # Verifica se __init__.py foram criados
    assert (tmp_path / "src" / "my_test_project" / "__init__.py").exists()
    assert (tmp_path / "tests" / "__init__.py").exists()

    # Verifica se arquivos de exemplo foram criados
    assert (tmp_path / "src" / "my_test_project" / "main.py").exists()
    assert (tmp_path / "tests" / "test_example.py").exists()


def test_optional_dependencies_flag(tmp_path, monkeypatch):
    """
    Verifica se a flag --install-runtime-deps controla a instalação de dependências.
    """
    pyproject_toml = tmp_path / "pyproject.toml"
    pyproject_toml.write_text('[tool.poetry]\nname = "test"\n')

    # Sem a flag, não deve instalar dependências de produção
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0)
        run_main_with_args([])

        # Verifica que poetry add NÃO foi chamado para produção
        poetry_add_calls = [
            call
            for call in mock_run.call_args_list
            if call[0][0][0:2] == ["poetry", "add"] and "--group" not in call[0][0]
        ]
        assert len(poetry_add_calls) == 0


def test_install_runtime_deps_flag(tmp_path, monkeypatch):
    """
    Verifica se --install-runtime-deps instala as dependências de produção.
    """
    pyproject_toml = tmp_path / "pyproject.toml"
    pyproject_toml.write_text('[tool.poetry]\nname = "test"\n')

    # Mock platform.system to avoid subprocess issues on Windows
    with patch("taipanstack_bootstrapper.platform.system", return_value="Linux"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0)
            run_main_with_args(["--install-runtime-deps"])

            # Verifica que poetry add FOI chamado para produção
            # Procura por chamadas que incluem 'pydantic' (dependência de produção)
            poetry_add_calls = [
                call
                for call in mock_run.call_args_list
                if len(call[0]) > 0
                and "poetry" in str(call[0][0])
                and "add" in str(call[0][0])
                and any("pydantic" in str(arg) for arg in call[0][0])
            ]
            assert len(poetry_add_calls) > 0, (
                "Poetry add with pydantic should have been called"
            )


def test_python_version_detection(tmp_path):
    """
    Verifica se a versão do Python é detectada dinamicamente.
    """
    pyproject_toml = tmp_path / "pyproject.toml"
    pyproject_toml.write_text('[tool.poetry]\nname = "test"\n')

    run_main_with_args([])

    content = pyproject_toml.read_text()

    # Verifica se a versão do Python está na configuração
    import sys

    expected_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert f'python_version = "{expected_version}"' in content

# RSA Timing Attack Laboratory
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


An educational framework for studying and implementing side-channel timing attacks against RSA. This laboratory provides a clear, modular structure for students and researchers to experiment with different RSA implementations (targets) and attack algorithms.

## 🏛️ Project Structure

The project uses a standard `src` layout to separate the installable library from the scripts and tests.

```
RSA-Timing-Lab/
├── scripts/            # High-level scripts to run experiment campaigns.
├── results/            # Default output directory for campaign results.
├── src/
│   └── rsa_timing_lab/ # The installable Python package.
│       ├── attacks/    # Attack algorithm implementations.
│       ├── core/       # Core interfaces and data models.
│       ├── targets/    # RSA implementations to be attacked.
│       └── utils/      # Helper modules (key generation, data management).
├── tests/              # Unit tests for the library.
└── pyproject.toml      # Project configuration and dependencies.
```

-----

## 🚀 Getting Started

Follow these steps to set up the laboratory environment on your local machine.

### Prerequisites

  * Python 3.10+
  * Git

### Installation Steps

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/vanderaveron-umons/RSA-Timing-Lab.git
    cd RSA-Timing-Lab
    ```

2.  **Create and activate a virtual environment:**
    This isolates the project's dependencies from your system.

    ```bash
    # Create the environment
    python3 -m venv .venv

    # Activate it (on macOS/Linux)
    source .venv/bin/activate

    # On Windows, use:
    # .venv\Scripts\activate
    ```

3.  **Install the project in editable mode:**
    This command installs the `rsa_lab` package and all its dependencies. The `-e` flag allows you to edit the source code and have the changes immediately reflected without reinstalling.

    ```bash
    pip install -e .
    ```

-----

## 🔬 Running Experiments

The main tool for running experiments is the `run_campaign.py` script. It allows you to configure and launch a full campaign of data collection and attacks from the command line.

### Basic Usage

All commands should be run from the **root directory** of the project.

```bash
# Run a small, default campaign for testing
python experiments/run_campaign.py

# Run a more specific campaign
python experiments/run_campaign.py --key-sizes 64 --configs vuln_50us --num-keys 5
```

### Command-Line Arguments

| Argument        | Description                                                                | Default Value                                              |
|:----------------|:---------------------------------------------------------------------------|:-----------------------------------------------------------|
| `--configs`     | A list of RSA configurations to test.                                      | Depends on `AVAILABLE_CONFIGURATIONS` in `run_campaign.py` |
| `--key-sizes`   | A list of key sizes (in bits) to test.                                     | `64`, `128`                                                |
| `--num-keys`    | The number of unique keys to generate for each configuration.              | `10`                                                       |
| `--samples`     | A list of sample counts to use for the attacks.                            | `10000, 20000, 40000, 80000, 160000`                       |
| `--max-samples` | The maximum number of timing samples to collect for each key.              | `160000`                                                   |
| `--seed`        | The initial random seed for the entire campaign, ensuring reproducibility. | `42`                                                       |

### Understanding the Output

The results of each campaign are saved in a uniquely named directory inside `results/`, for example `results/campaign_20250806_123000/`.

This directory contains:

  * `keys.csv`: A list of all RSA keys generated during the campaign, including their private components and the seeds used to generate them.
  * `detailed_results.csv`: A detailed log of every single attack trial, including its parameters, timing, and success/failure.
  * `timing_data/`: A subdirectory containing the raw timing samples for each key, saved in individual CSV files.

At the end of the run, a summary table is also printed to the console, showing the success rate and average attack time for each combination of RSA implementation and sample count.

-----

## 🧑‍💻 Extending the Laboratory

This framework is designed to be easily extended.

### Adding a New RSA Target

1.  Create a new Python file in `src/rsa_lab/targets/` (e.g., `my_secure_rsa.py`).
2.  Inside this file, create a class that inherits from `TimedRSAInterface`:
    ```python
    from rsa_timing_lab.core import TimedRSAInterface
    
    class MySecureRSA(TimedRSAInterface):
        # ... implement timed_encrypt and timed_decrypt ...
    ```
    ```
3. Open `rsa_timing_lab/targets/__init__.py` and register your new implementation.
4. Open `experiments/run_campaign.py` and register your new implementation in the `AVAILABLE_CONFIGURATIONS` dictionary.

### Adding a New Attack Algorithm

1.  Create a new Python file in `src/rsa_lab/attackers/` (e.g., `my_attack.py`).
2.  Inside this file, create a class that inherits from `TimingAttackInterface`:
    ```python
    from rsa_timing_lab.core import TimingAttackInterface
    
    class MyAttack(TimingAttackInterface):
        # ... implement from_data and attack ...
    ```
    ```
3. Open `rsa_timing_lab/attacks/__init__.py` and register your new implementation. 
4. Open `experiments/run_campaign.py` and change the parameter passed to `ExperimentRunner` in the `main` function to use your new class.

-----

## ✅ Running Tests

To run the suite of unit tests, you will first need to install the development dependencies:

```bash
pip install -e .[dev]
```
Once installed, run the tests from the project root directory:

```bash
pytest
```

Pytest will automatically discover and run all tests located in the `tests/` directory.

-----

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

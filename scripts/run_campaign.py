import os
import argparse
import multiprocessing
import pandas as pd
from datetime import datetime
from typing import List, Dict, Tuple
from dataclasses import dataclass, asdict

from rsa_timing_lab.core import TimingAttackInterface
from rsa_timing_lab.targets import VulnerableRSA
from rsa_timing_lab.attacks import DhemAttack
from rsa_timing_lab.utils.rsa_key_generator import RSAKeyGenerator
from rsa_timing_lab.utils.timing_data_collector import TimingDataCollector
from rsa_timing_lab.utils import data_manager

# --- 1. Define Testable Configurations ---
# This is where you can easily add new RSA implementations to test.
AVAILABLE_CONFIGURATIONS = {
    "vuln_0us":   {"class": VulnerableRSA, "params": {"sleep_duration": 0.0}},
    "vuln_10us":  {"class": VulnerableRSA, "params": {"sleep_duration": 0.00001}},
    "vuln_50us":  {"class": VulnerableRSA, "params": {"sleep_duration": 0.00005}},
    "vuln_100us": {"class": VulnerableRSA, "params": {"sleep_duration": 0.0001}},
    # Example for a future secure implementation:
    # "secure_v1": {"class": SecureRSA, "params": {}},
}


# --- 2. Data Structures for the Experiment ---
@dataclass
class ExperimentConfig:
    """Configuration for a single data collection trial."""
    trial_id: str
    rsa_config_name: str
    key_size: int
    key_seed: int
    sample_seed: int


@dataclass
class TrialResult:
    """Result of a single attack trial."""
    trial_id: str
    rsa_config_name: str
    key_size: int
    samples_used: int
    success: bool
    attack_time: float
    collection_time: float


# --- 3. Worker Functions for Multiprocessing (must be top-level) ---
def _collect_worker(task: Tuple) -> Tuple:
    """Generates a key and collects timing samples for one configuration."""
    config, rsa_instance, num_samples = task
    key = RSAKeyGenerator.generate_keypair(config.key_size, seed=config.key_seed)
    collector = TimingDataCollector(rsa_instance)
    timing_data, collection_time = collector.collect_samples(key, num_samples, config.sample_seed)
    return config, key, timing_data, collection_time


def _attack_worker(task: Tuple) -> TrialResult:
    """Runs an attack on a single set of collected data."""
    config, key, timing_data, collection_time, sample_count, attack_class = task
    attack_instance = attack_class.from_data(key.public_key, timing_data)
    attack_result = attack_instance.attack(limit_max_samples=sample_count)
    success = (int(attack_result.recovered_key_bits, 2) == key.d)
    return TrialResult(
        trial_id=config.trial_id,
        rsa_config_name=config.rsa_config_name,
        key_size=config.key_size,
        samples_used=attack_result.samples_used,
        success=success,
        attack_time=attack_result.attack_time,
        collection_time=collection_time,
    )


# --- 4. Main Experiment Orchestrator ---
class ExperimentRunner:
    """Orchestrates the entire experimental campaign."""

    def __init__(self, rsa_configs: Dict[str, Dict], attack_class: type[TimingAttackInterface]):
        self.rsa_instances = {name: cfg["class"](**cfg["params"]) for name, cfg in rsa_configs.items()}
        self.attack_class = attack_class
        self.campaign_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join("results", f"campaign_{self.campaign_id}")
        self.timing_data_dir = os.path.join(self.output_dir, "timing_data")
        os.makedirs(self.timing_data_dir, exist_ok=True)

    def run_campaign(self, key_sizes: List[int], num_keys: int, sample_counts: List[int], max_samples: int, seed: int):
        print("Starting RSA Timing Attack Experiment Campaign")
        print("=" * 50)
        print(f"Campaign ID: {self.campaign_id}")
        print(f"Results will be saved in: {self.output_dir}")
        print("-" * 50)
        print("Parameters:")
        print(f"  - RSA Configurations: {list(self.rsa_instances.keys())}")
        print(f"  - Key Sizes: {key_sizes} bits")
        print(f"  - Keys per Config: {num_keys}")
        print(f"  - Attack Sample Counts: {sample_counts}")
        print(f"  - Max Samples to Collect: {max_samples}")
        print(f"  - Initial Random Seed: {seed}")
        print("=" * 50)

        configs = self._generate_configs(key_sizes, num_keys, seed)
        collection_results = self._collect_all_data(configs, max_samples)

        # Save keys and timing data immediately after collection
        self._save_collection_data(collection_results)

        attack_results = self._run_all_attacks(collection_results, sample_counts)
        self._generate_report(attack_results)

        print("\nCampaign finished successfully.")

    def _generate_configs(self, key_sizes: List[int], num_keys: int, initial_seed: int) -> List[ExperimentConfig]:
        configs = []
        seed = initial_seed
        for rsa_name in self.rsa_instances.keys():
            for key_size in key_sizes:
                for key_id in range(num_keys):
                    configs.append(ExperimentConfig(
                        trial_id=f"{rsa_name}_ks{key_size}_key{key_id:02d}",
                        rsa_config_name=rsa_name,
                        key_size=key_size,
                        key_seed=seed,
                        sample_seed=seed + 1_000_000
                    ))
                    seed += 1
        return configs

    def _collect_all_data(self, configs: List[ExperimentConfig], num_samples: int) -> List[Tuple]:
        tasks = [(cfg, self.rsa_instances[cfg.rsa_config_name], num_samples) for cfg in configs]
        with multiprocessing.Pool() as pool:
            results = pool.map(_collect_worker, tasks)
        # We need to map the generated key to the trial_id for saving
        return [(cfg, key, data, time) for cfg, key, data, time in results]

    def _save_collection_data(self, collection_results: List[Tuple]):
        print("\n   Saving keys and timing data with seeds for reproducibility...")

        keys_to_save = {res[0].trial_id: (res[1], res[0]) for res in
                        collection_results}  # {trial_id: (RSAKey, ExperimentConfig)}
        data_manager.export_keys(os.path.join(self.output_dir, "keys.csv"), keys_to_save)

        for config, key, timing_data, _ in collection_results:
            timing_filename = os.path.join(self.timing_data_dir, f"{config.trial_id}.csv")
            metadata = {"trial_id": config.trial_id, "key_size": key.n.bit_length()}
            data_manager.export_timing_data(timing_filename, timing_data, metadata)

    def _run_all_attacks(self, collection_results: List[Tuple], sample_counts: List[int]) -> List[TrialResult]:
        tasks = []
        for config, key, timing_data, collection_time in collection_results:
            for count in sample_counts:
                if count <= len(timing_data):
                    tasks.append((config, key, timing_data, collection_time, count, self.attack_class))
        with multiprocessing.Pool() as pool:
            return pool.map(_attack_worker, tasks)

    def _generate_report(self, results: List[TrialResult]):
        print("\n   Generating reports...")
        if not results:
            print("    -> No results to report.")
            return

        # Export detailed results
        detailed_filename = os.path.join(self.output_dir, "detailed_results.csv")
        data_manager.export_attack_results(detailed_filename, results)
        print(f"    -> Detailed results saved to {detailed_filename}")

        results_as_dicts = [asdict(r) for r in results]
        self._print_summary_report(results_as_dicts)

    def _print_summary_report(self, results_as_dicts: List[Dict]):
        """Calculates and prints a summary table of the campaign results."""
        df = pd.DataFrame(results_as_dicts)

        # Obtenir les paramètres uniques de la campagne
        key_sizes = sorted(df['key_size'].unique())
        num_keys = df.groupby(['rsa_config_name', 'key_size'])['trial_id'].nunique().iloc[0]

        print("\n" + "=" * 80)
        print("📊 CAMPAIGN SUMMARY")
        print("=" * 80)

        for key_size in key_sizes:
            print(f"\n--- Key Size: {key_size} bits ({num_keys} keys tested per configuration) ---")
            print(f"Percentage of attack success and average attack time in seconds.\n")

            # Filtrer les données pour la taille de clé actuelle
            ks_df = df[df['key_size'] == key_size]

            # Pivoter le tableau pour avoir les samples en colonnes
            summary = ks_df.groupby(['rsa_config_name', 'samples_used']).agg(
                success_rate=('success', 'mean'),
                avg_attack_time=('attack_time', 'mean')
            ).unstack()

            # Formater les cellules
            formatted_summary = summary.apply(
                lambda row: [f"{row[('success_rate', sc)] * 100:3.0f}% ({row[('avg_attack_time', sc)]:.2f}s)" for sc in
                             summary.columns.levels[1]],
                axis=1,
                result_type='expand'
            )
            formatted_summary.columns = [f"{sc} samples" for sc in summary.columns.levels[1]]

            # Ajouter la colonne du temps de collecte moyen
            avg_collection_time = ks_df.groupby('rsa_config_name')['collection_time'].mean()
            formatted_summary['Avg Collect Time'] = avg_collection_time.map('{:.2f}s'.format)

            print(formatted_summary.to_string())
            print("-" * 80)

# --- 5. Script Entry Point and Argument Parsing ---
def main():
    parser = argparse.ArgumentParser(description="Run an RSA Timing Attack Experiment Campaign.")
    parser.add_argument('--configs', nargs='+', default=["vuln_0us", "vuln_10us", "vuln_50us", "vuln_100us"],
                        choices=AVAILABLE_CONFIGURATIONS.keys(), help="List of RSA configurations to test.")
    parser.add_argument('--key-sizes', type=int, nargs='+', default=[64, 128], help="List of key sizes to test.")
    parser.add_argument('--num-keys', type=int, default=10, help="Number of keys to generate per config.")
    parser.add_argument('--samples', type=int, nargs='+', default=[10000, 20000, 40000, 80000, 160000],
                        help="List of sample counts for attacks.")
    parser.add_argument('--max-samples', type=int, default=160000, help="Maximum number of samples to collect per key.")
    parser.add_argument('--seed', type=int, default=42, help="Initial random seed for reproducibility.")
    args = parser.parse_args()

    selected_configs = {name: AVAILABLE_CONFIGURATIONS[name] for name in args.configs}
    runner = ExperimentRunner(selected_configs, DhemAttack)
    runner.run_campaign(
        key_sizes=args.key_sizes,
        num_keys=args.num_keys,
        sample_counts=args.samples,
        max_samples=args.max_samples,
        seed=args.seed
    )


if __name__ == '__main__':
    main()
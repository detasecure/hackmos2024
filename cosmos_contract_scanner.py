import os
import json
import re
import argparse
from datetime import datetime
from typing import List, Dict, Any


class Vulnerability:
    def __init__(self, vuln_type: str, description: str, location: str, line_number: int, severity: str,
                 root_cause: str):
        self.vuln_type = vuln_type
        self.description = description
        self.location = location
        self.line_number = line_number
        self.severity = severity
        self.root_cause = root_cause


class CosmosContractScanner:
    def __init__(self, contract_file: str):
        self.contract_file = contract_file
        self.vulnerabilities: List[Vulnerability] = []

    def scan_file(self) -> None:
        if not os.path.isfile(self.contract_file):
            print(f"File {self.contract_file} not found.")
            return

        try:
            with open(self.contract_file, 'r') as file:
                lines = file.readlines()
                self.check_insecure_randomness(lines)
                self.check_unchecked_gas_usage(lines)
                self.check_ibc_unprotected_calls(lines)
                self.check_reentrancy(lines)
                # self.check_unchecked_math(lines)
                self.check_error_handling(lines)
        except Exception as e:
            print(f"Error scanning file {self.contract_file}: {e}")

    # Security Checks
    def check_insecure_randomness(self, lines: List[str]) -> None:
        for i, line in enumerate(lines, 1):
            if "env::random()" in line:
                self.vulnerabilities.append(Vulnerability(
                    "Insecure Randomness",
                    "Use of env::random() detected, which is predictable",
                    self.contract_file,
                    i,
                    "High",
                    "Predictable randomness can lead to attacks on contract logic"
                ))

    def check_unchecked_gas_usage(self, lines: List[str]) -> None:
        for i, line in enumerate(lines, 1):
            if "env::gas_left()" in line and "assert!" not in line:
                self.vulnerabilities.append(Vulnerability(
                    "Unchecked Gas Usage",
                    "Gas usage is unbounded; may lead to out-of-gas errors",
                    self.contract_file,
                    i,
                    "Medium",
                    "Lack of gas checks can result in transaction failures"
                ))

    def check_ibc_unprotected_calls(self, lines: List[str]) -> None:
        for i, line in enumerate(lines, 1):
            if "IbcMsg::" in line and "assert!(env::predecessor_account_id()" not in line:
                self.vulnerabilities.append(Vulnerability(
                    "Unprotected IBC Call",
                    "IBC call without access control detected",
                    self.contract_file,
                    i,
                    "High",
                    "Unprotected IBC calls could be exploited by unauthorized actors"
                ))

    def check_reentrancy(self, lines: List[str]) -> None:
        for i, line in enumerate(lines, 1):
            if "call_contract" in line and "self." in line:
                self.vulnerabilities.append(Vulnerability(
                    "Reentrancy Vulnerability",
                    "Reentrancy issue detected; state changes after external calls",
                    self.contract_file,
                    i,
                    "High",
                    "Reentrancy issues can lead to fund loss or unexpected behavior"
                ))

    def check_unchecked_math(self, lines: List[str]) -> None:
        for i, line in enumerate(lines, 1):
            if re.search(r'\+|-|\*|/', line) and 'checked_' not in line:
                self.vulnerabilities.append(Vulnerability(
                    "Unchecked Math Operations",
                    "Unchecked arithmetic operation detected; use checked_*",
                    self.contract_file,
                    i,
                    "High",
                    "Unchecked math can lead to overflows or underflows"
                ))

    def check_error_handling(self, lines: List[str]) -> None:
        for i, line in enumerate(lines, 1):
            if 'panic!' in line or 'unwrap' in line:
                self.vulnerabilities.append(Vulnerability(
                    "Improper Error Handling",
                    "Use of panic or unwrap detected; handle errors gracefully",
                    self.contract_file,
                    i,
                    "Medium",
                    "Improper error handling can lead to unexpected contract terminations"
                ))

    def scan(self) -> List[Vulnerability]:
        self.scan_file()
        return self.vulnerabilities

    def generate_report(self) -> Dict[str, Any]:
        return {
            "contract_file": self.contract_file,
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "description": v.description,
                    "location": f"{v.location}:{v.line_number}",
                    "severity": v.severity,
                    "root_cause": v.root_cause
                } for v in self.vulnerabilities
            ],
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "high_severity": sum(1 for v in self.vulnerabilities if v.severity == "High"),
                "medium_severity": sum(1 for v in self.vulnerabilities if v.severity == "Medium"),
                "low_severity": sum(1 for v in self.vulnerabilities if v.severity == "Low")
            }
        }


def main():
    parser = argparse.ArgumentParser(description="Cosmos Smart Contract Security Scanner")
    parser.add_argument("contract_file", help="Path to the Cosmos smart contract file")
    args = parser.parse_args()

    # Initialize and run scanner
    scanner = CosmosContractScanner(args.contract_file)
    scanner.scan()
    report = scanner.generate_report()

    # Print report to console
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

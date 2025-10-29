#!/usr/bin/env python3
"""
Subdomain Enumerator and IP Validator created by Lada Slobodska and Claude

A tool for discovering subdomains via crt.sh and validating their IP addresses
against a defined scope.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Set, Dict, Tuple
import requests
import json
import time
import subprocess
import socket
import ipaddress
from urllib.parse import quote

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Handles subdomain discovery via crt.sh certificate transparency logs."""
    
    def __init__(self, output_file: str = "results_subdomains.txt"):
        self.output_file = output_file
        self.discovered_subdomains: Set[str] = set()
        
    def normalize_domain(self, domain: str) -> str:
        """
        Normalize a domain name by:
        - Converting to lowercase
        - Removing wildcard prefixes (*.example.com -> example.com)
        - Stripping trailing dots
        
        Args:
            domain: Raw domain string
            
        Returns:
            Normalized domain string
        """
        domain = domain.lower().strip()
        if domain.startswith('*.'):
            domain = domain[2:]
        domain = domain.rstrip('.')
        return domain
    
    def query_crtsh(self, domain: str) -> Set[str]:
        """
        Query crt.sh for subdomains of the given domain.
        
        Args:
            domain: Target domain to search
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        
        logger.info(f"Querying crt.sh for domain: {domain}")
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for entry in data:
                if 'name_value' in entry:
                    # name_value can contain multiple domains separated by newlines
                    names = entry['name_value'].split('\n')
                    for name in names:
                        normalized = self.normalize_domain(name)
                        if normalized:
                            subdomains.add(normalized)
            
            logger.info(f"Found {len(subdomains)} unique subdomains for {domain}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying crt.sh for {domain}: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON response for {domain}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error for {domain}: {e}")
        
        # Small delay to be respectful to crt.sh
        time.sleep(1)
        
        return subdomains
    
    def enumerate_domains(self, domains: List[str]) -> Set[str]:
        """
        Enumerate subdomains for a list of target domains.
        
        Args:
            domains: List of target domains
            
        Returns:
            Set of all discovered subdomains
        """
        all_subdomains = set()
        
        for domain in domains:
            subdomains = self.query_crtsh(domain)
            all_subdomains.update(subdomains)
        
        self.discovered_subdomains.update(all_subdomains)
        return all_subdomains
    
    def save_results(self) -> None:
        """Save discovered subdomains to output file."""
        try:
            with open(self.output_file, 'w') as f:
                for subdomain in sorted(self.discovered_subdomains):
                    f.write(f"{subdomain}\n")
            logger.info(f"Results saved to {self.output_file}")
        except IOError as e:
            logger.error(f"Error saving results to {self.output_file}: {e}")
    
    def print_results(self) -> None:
        """Print discovered subdomains to console."""
        if not self.discovered_subdomains:
            print("\nNo subdomains discovered.")
            return
        
        print(f"\n{'='*60}")
        print(f"Discovered Subdomains ({len(self.discovered_subdomains)} total)")
        print(f"{'='*60}")
        for subdomain in sorted(self.discovered_subdomains):
            print(f"  • {subdomain}")
        print(f"{'='*60}\n")


class IPValidator:
    """Validates domain IP addresses against a defined scope."""
    
    def __init__(self, scope_file: str):
        self.scope_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.load_scope(scope_file)
    
    def load_scope(self, scope_file: str) -> None:
        """
        Load IP scope from file.
        
        Args:
            scope_file: Path to file containing IPs/networks
        """
        logger.info(f"Loading IP scope from {scope_file}")
        
        try:
            with open(scope_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Handle hyphenated ranges
                        if '-' in line and '/' not in line:
                            start_ip, end_ip = line.split('-')
                            start = ipaddress.ip_address(start_ip.strip())
                            end = ipaddress.ip_address(end_ip.strip())
                            
                            # Convert range to networks
                            networks = ipaddress.summarize_address_range(start, end)
                            self.scope_networks.extend(networks)
                        else:
                            # Handle CIDR or single IP
                            network = ipaddress.ip_network(line, strict=False)
                            self.scope_networks.append(network)
                    
                    except ValueError as e:
                        logger.warning(f"Invalid IP/network format: {line} - {e}")
            
            logger.info(f"Loaded {len(self.scope_networks)} networks into scope")
        
        except IOError as e:
            logger.error(f"Error reading scope file {scope_file}: {e}")
            raise
    
    def resolve_domain(self, domain: str) -> List[str]:
        """
        Resolve domain to IP addresses.
        First attempts using 'host' command, falls back to socket module.
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            List of resolved IP addresses
        """
        ips = []
        
        # Try using host command first
        try:
            result = subprocess.run(
                ['host', domain],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'has address' in line or 'has IPv6 address' in line:
                        parts = line.split()
                        if parts:
                            ip = parts[-1]
                            try:
                                ipaddress.ip_address(ip)
                                ips.append(ip)
                            except ValueError:
                                continue
                
                if ips:
                    return ips
        
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            logger.debug(f"'host' command failed for {domain}, using fallback")
        
        # Fallback to socket module
        try:
            # Get both IPv4 and IPv6 addresses
            addr_info = socket.getaddrinfo(domain, None)
            for info in addr_info:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        
        except socket.gaierror:
            logger.debug(f"Could not resolve {domain}")
        except Exception as e:
            logger.debug(f"Error resolving {domain}: {e}")
        
        return ips
    
    def is_ip_in_scope(self, ip_str: str) -> bool:
        """
        Check if an IP address is within the defined scope.
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if IP is in scope, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.scope_networks:
                if ip in network:
                    return True
        except ValueError:
            logger.warning(f"Invalid IP address: {ip_str}")
        
        return False
    
    def validate_domains(self, domains: List[str]) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """
        Validate domains against IP scope.
        
        Args:
            domains: List of domains to validate
            
        Returns:
            Tuple of (in_scope_dict, out_of_scope_dict)
        """
        in_scope = {}
        out_of_scope = {}
        
        logger.info(f"Validating {len(domains)} domains against IP scope")
        
        for domain in domains:
            ips = self.resolve_domain(domain)
            
            if not ips:
                logger.debug(f"No IPs resolved for {domain}")
                continue
            
            in_scope_ips = [ip for ip in ips if self.is_ip_in_scope(ip)]
            
            if in_scope_ips:
                in_scope[domain] = ips
            else:
                out_of_scope[domain] = ips
        
        return in_scope, out_of_scope
    
    def save_validation_results(
        self,
        in_scope: Dict[str, List[str]],
        out_of_scope: Dict[str, List[str]]
    ) -> None:
        """
        Save validation results to files.
        
        Args:
            in_scope: Dictionary of in-scope domains and their IPs
            out_of_scope: Dictionary of out-of-scope domains and their IPs
        """
        try:
            with open('in_scope_domains.txt', 'w') as f:
                for domain, ips in sorted(in_scope.items()):
                    f.write(f"{domain} - {','.join(ips)}\n")
            logger.info(f"In-scope domains saved to in_scope_domains.txt")
        except IOError as e:
            logger.error(f"Error saving in-scope results: {e}")
        
        try:
            with open('out_of_scope_domains.txt', 'w') as f:
                for domain, ips in sorted(out_of_scope.items()):
                    f.write(f"{domain} - {','.join(ips)}\n")
            logger.info(f"Out-of-scope domains saved to out_of_scope_domains.txt")
        except IOError as e:
            logger.error(f"Error saving out-of-scope results: {e}")
    
    def print_validation_results(
        self,
        in_scope: Dict[str, List[str]],
        out_of_scope: Dict[str, List[str]]
    ) -> None:
        """
        Print validation results to console.
        
        Args:
            in_scope: Dictionary of in-scope domains and their IPs
            out_of_scope: Dictionary of out-of-scope domains and their IPs
        """
        print(f"\n{'='*60}")
        print(f"In-Scope Domains ({len(in_scope)} total)")
        print(f"{'='*60}")
        if in_scope:
            for domain, ips in sorted(in_scope.items()):
                print(f"  • {domain} → {', '.join(ips)}")
        else:
            print("  (none)")
        print(f"{'='*60}\n")
        
        print(f"\n{'='*60}")
        print(f"Out-of-Scope Domains ({len(out_of_scope)} total)")
        print(f"{'='*60}")
        if out_of_scope:
            for domain, ips in sorted(out_of_scope.items()):
                print(f"  • {domain} → {', '.join(ips)}")
        else:
            print("  (none)")
        print(f"{'='*60}\n")


def read_domains_file(filepath: str) -> List[str]:
    """
    Read domains from a text file.
    
    Args:
        filepath: Path to domains file
        
    Returns:
        List of domain names
    """
    domains = []
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    except IOError as e:
        logger.error(f"Error reading domains file {filepath}: {e}")
        raise
    
    return domains


def interactive_menu(enumerator: SubdomainEnumerator) -> int:
    """
    Display interactive menu and get user choice.
    
    Args:
        enumerator: SubdomainEnumerator instance
        
    Returns:
        User's menu choice (0, 1, or 2)
    """
    print("\n" + "="*60)
    print("Next Actions")
    print("="*60)
    print("  0 - Exit")
    print("  1 - Find sub-subdomains for discovered subdomains")
    print("  2 - Validate IP addresses against scope")
    print("="*60)
    
    while True:
        try:
            choice = input("\nEnter your choice (0-2): ").strip()
            choice_int = int(choice)
            if choice_int in [0, 1, 2]:
                return choice_int
            else:
                print("Invalid choice. Please enter 0, 1, or 2.")
        except ValueError:
            print("Invalid input. Please enter a number (0, 1, or 2).")
        except EOFError:
            print("\nExiting.")
            return 0


def main():
    """Main entry point for the subdomain enumerator tool."""
    parser = argparse.ArgumentParser(
        description="Subdomain Enumerator and IP Validator by Lada Slobodska and Claude",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (default)
  python subdomain_enumerator.py -d domains.txt
  
  # Non-interactive mode: enumerate only
  python subdomain_enumerator.py -d domains.txt --non-interactive
  
  # Non-interactive mode: enumerate and validate
  python subdomain_enumerator.py -d domains.txt --non-interactive --validate --scope scope.txt
  
  # Non-interactive mode: enumerate and find sub-subdomains
  python subdomain_enumerator.py -d domains.txt --non-interactive --recursive
        """
    )
    
    parser.add_argument(
        '-d', '--domains',
        required=True,
        help='Path to file containing target domains (one per line)'
    )
    
    parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Run in non-interactive mode'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='Find sub-subdomains (non-interactive mode only)'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate IPs against scope (non-interactive mode only)'
    )
    
    parser.add_argument(
        '--scope',
        help='Path to file containing IP scope (required with --validate)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='results_subdomains.txt',
        help='Output file for discovered subdomains (default: results_subdomains.txt)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Validate arguments
    if args.validate and not args.scope:
        parser.error("--validate requires --scope to be specified")
    
    if (args.recursive or args.validate) and not args.non_interactive:
        parser.error("--recursive and --validate can only be used with --non-interactive")
    
    # Read target domains
    try:
        target_domains = read_domains_file(args.domains)
        if not target_domains:
            logger.error("No domains found in input file")
            return 1
        logger.info(f"Loaded {len(target_domains)} target domains")
    except Exception as e:
        logger.error(f"Failed to read domains file: {e}")
        return 1
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(output_file=args.output)
    
    # Initial enumeration
    print("\nStarting subdomain enumeration...")
    enumerator.enumerate_domains(target_domains)
    enumerator.save_results()
    enumerator.print_results()
    
    # Handle non-interactive mode
    if args.non_interactive:
        if args.recursive:
            print("\nEnumerating sub-subdomains...")
            current_subdomains = list(enumerator.discovered_subdomains)
            new_subdomains = enumerator.enumerate_domains(current_subdomains)
            if new_subdomains:
                enumerator.save_results()
                enumerator.print_results()
            else:
                print("No additional sub-subdomains found.")
        
        if args.validate:
            print("\nValidating IP addresses against scope...")
            validator = IPValidator(args.scope)
            domains_to_validate = list(enumerator.discovered_subdomains)
            in_scope, out_of_scope = validator.validate_domains(domains_to_validate)
            validator.save_validation_results(in_scope, out_of_scope)
            validator.print_validation_results(in_scope, out_of_scope)
        
        return 0
    
    # Interactive mode
    while True:
        choice = interactive_menu(enumerator)
        
        if choice == 0:
            print("\nExiting. Thank you for using Subdomain Enumerator!")
            break
        
        elif choice == 1:
            print("\nEnumerating sub-subdomains...")
            current_subdomains = list(enumerator.discovered_subdomains)
            new_subdomains = enumerator.enumerate_domains(current_subdomains)
            if new_subdomains:
                enumerator.save_results()
                enumerator.print_results()
            else:
                print("No additional sub-subdomains found.")
        
        elif choice == 2:
            scope_file = input("\nEnter path to IP scope file: ").strip()
            try:
                validator = IPValidator(scope_file)
                domains_to_validate = list(enumerator.discovered_subdomains)
                in_scope, out_of_scope = validator.validate_domains(domains_to_validate)
                validator.save_validation_results(in_scope, out_of_scope)
                validator.print_validation_results(in_scope, out_of_scope)
            except Exception as e:
                logger.error(f"Validation failed: {e}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

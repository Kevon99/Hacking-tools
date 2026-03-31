#!/usr/bin/env python3
"""
DXt Miner - High-Performance Data Leak Mining Tool
Author: Senior Cybersecurity Developer
Purpose: Massive file mining (10GB+) for data leaks with streaming processing
"""

import argparse
import re
import sys
import time
from pathlib import Path
from typing import Generator, Set


class DXtaMiner:
    """High-performance data leak miner with streaming processing"""
    
    # Auto-Recon regex patterns (obligatory searches)
    AUTO_RECON_PATTERNS = {
        'uuid': re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE),
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'aws_key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'js_file': re.compile(r'\b[^/\s]+\.js(\?[^/\s]*)?\b'),
        'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    }
    
    def __init__(self, data_file: Path, wordlist_file: Path):
        """
        Initialize DXtaMiner with data and wordlist files
        
        Args:
            data_file: Path to the massive data file
            wordlist_file: Path to the dictionary/wordlist file
        """
        self.data_file = data_file
        self.wordlist_file = wordlist_file
        self.word_set: Set[str] = set()
        self.stats = {
            'lines_processed': 0,
            'dict_matches': 0,
            'auto_recon_matches': 0,
            'start_time': 0,
            'end_time': 0
        }
        
    def load_wordlist(self) -> None:
        """Load wordlist into memory as a set for O(1) lookups"""
        print(f" Loading wordlist: {self.wordlist_file}")
        
        try:
            with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Remove comments and whitespace, convert to lowercase
                    clean_word = line.split('#', 1)[0].strip().lower()
                    if clean_word:  # Only add non-empty words
                        self.word_set.add(clean_word)
                    
                    # Progress indicator for large wordlists
                    if line_num % 10000 == 0:
                        print(f"   Loaded {line_num:,} words...")
                        
        except FileNotFoundError:
            print(f" ERROR: Wordlist file not found: {self.wordlist_file}")
            sys.exit(1)
        except Exception as e:
            print(f" ERROR: Failed to load wordlist: {e}")
            sys.exit(1)
            
        print(f" Wordlist loaded: {len(self.word_set):,} words")
    
    def stream_file(self) -> Generator[str, None, None]:
        """
        Stream file line by line without loading into RAM
        
        Yields:
            str: Each line from the data file
        """
        try:
            with open(self.data_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line
        except FileNotFoundError:
            print(f" ERROR: Data file not found: {self.data_file}")
            sys.exit(1)
        except Exception as e:
            print(f" ERROR: Failed to read data file: {e}")
            sys.exit(1)
    
    def setup_output_directories(self) -> tuple[Path, Path, Path]:
        """
        Create output directory structure
        
        Returns:
            tuple: (gold_dir, dict_output_dir, auto_recon_file)
        """
        gold_dir = Path("gold")
        dict_name = self.wordlist_file.stem
        dict_output_dir = gold_dir / dict_name
        auto_recon_file = gold_dir / "auto_recon_obligatory.txt"
        
        # Create directories
        gold_dir.mkdir(exist_ok=True)
        dict_output_dir.mkdir(exist_ok=True)
        
        matches_file = dict_output_dir / "matches.txt"
        
        return gold_dir, dict_output_dir, matches_file, auto_recon_file
    
    def search_dictionary_words(self, line: str, line_lower: str) -> bool:
        """
        Search for dictionary words in line using substring matching
        
        Args:
            line: Original line for output
            line_lower: Lowercase version for searching
            
        Returns:
            bool: True if any dictionary word is found
        """
        return any(word in line_lower for word in self.word_set)
    
    def auto_recon_search(self, line: str) -> dict:
        """
        Perform Auto-Recon searches using compiled regex patterns
        
        Args:
            line: Line to search
            
        Returns:
            dict: Found matches by pattern type
        """
        matches = {}
        for pattern_name, pattern in self.AUTO_RECON_PATTERNS.items():
            found = pattern.findall(line)
            if found:
                matches[pattern_name] = found
        return matches
    
    def process_file(self) -> None:
        """Main processing function with streaming and dual search"""
        print(f"  Starting mining: {self.data_file}")
        print(f" Output will be saved in: gold/{self.wordlist_file.stem}/")
        
        # Setup output directories
        gold_dir, dict_output_dir, matches_file, auto_recon_file = self.setup_output_directories()
        
        # Start timing
        self.stats['start_time'] = time.time()
        
        try:
            with open(matches_file, 'w', encoding='utf-8') as dict_f, \
                 open(auto_recon_file, 'w', encoding='utf-8') as auto_f:
                
                print("🚀 Processing file (streaming mode)...")
                
                for line_num, line in enumerate(self.stream_file(), 1):
                    line_lower = line.lower()
                    dict_match_found = False
                    auto_recon_matches = {}
                    
                    # Dictionary word search
                    if self.word_set:
                        dict_match_found = self.search_dictionary_words(line, line_lower)
                    
                    # Auto-Recon search
                    auto_recon_matches = self.auto_recon_search(line)
                    
                    # Write matches to respective files
                    if dict_match_found:
                        dict_f.write(line)
                        self.stats['dict_matches'] += 1
                        dict_match_found = True
                    
                    if auto_recon_matches:
                        # Write formatted Auto-Recon matches
                        auto_f.write(f"LINE {line_num}: {line.strip()}\n")
                        for pattern_type, matches in auto_recon_matches.items():
                            for match in matches:
                                auto_f.write(f"  [{pattern_type.upper()}] {match}\n")
                        auto_f.write("---\n")
                        self.stats['auto_recon_matches'] += 1
                    
                    # Progress indicator
                    self.stats['lines_processed'] = line_num
                    if line_num % 100_000 == 0:
                        elapsed = time.time() - self.stats['start_time']
                        rate = line_num / elapsed if elapsed > 0 else 0
                        print(f"    Processed {line_num:,} lines | Rate: {rate:,.0f} lines/sec | Dict hits: {self.stats['dict_matches']:,} | Auto-Recon hits: {self.stats['auto_recon_matches']:,}")
                        
        except KeyboardInterrupt:
            print("\n  Process interrupted by user")
        except Exception as e:
            print(f" ERROR during processing: {e}")
        finally:
            self.stats['end_time'] = time.time()
    
    def print_summary(self) -> None:
        """Print final execution summary"""
        elapsed_time = self.stats['end_time'] - self.stats['start_time']
        
        print("\n" + "="*60)
        print(" DXta MINER - EXECUTION SUMMARY")
        print("="*60)
        print(f"⏱  Total execution time: {elapsed_time:.2f} seconds")
        print(f" Lines processed: {self.stats['lines_processed']:,}")
        print(f" Dictionary matches: {self.stats['dict_matches']:,}")
        print(f" Auto-Recon matches: {self.stats['auto_recon_matches']:,}")
        
        # Calculate processing rate
        if elapsed_time > 0:
            rate = self.stats['lines_processed'] / elapsed_time
            print(f" Average processing rate: {rate:,.0f} lines/second")
        
        print(f"\n Generated files:")
        print(f"    gold/{self.wordlist_file.stem}/matches.txt")
        print(f"    gold/auto_recon_obligatory.txt")
        print("="*60)


def compile_regex_engine():
    """Compile and test regex patterns (validation function)"""
    print("🔧 Testing Auto-Recon regex patterns...")
    
    test_cases = {
        'uuid': '550e8400-e29b-41d4-a716-446655440000',
        'jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        'aws_key': 'AKIAIOSFODNN7EXAMPLE',
        'email': 'user@example.com',
        'js_file': 'https://example.com/app.js?version=1.0',
        'ipv4': '192.168.1.1'
    }
    
    miner = DXtaMiner(Path("dummy"), Path("dummy"))
    
    for pattern_name, pattern in miner.AUTO_RECON_PATTERNS.items():
        test_value = test_cases.get(pattern_name, '')
        if pattern.search(test_value):
            print(f"    {pattern_name.upper()}: Pattern working")
        else:
            print(f"    {pattern_name.upper()}: Pattern failed")
    
    print(" Regex engine compilation complete\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="DXta Miner - High-Performance Data Leak Mining Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dxtaminer.py -d massive_log.txt -w secrets.txt
  python3 dxtaminer.py -d /path/to/data.log -w /path/to/wordlist.txt
        """
    )
    
    parser.add_argument(
        '-d', '--data',
        type=Path,
        required=True,
        help='Massive data file to mine (logs, URLs, etc.)'
    )
    
    parser.add_argument(
        '-w', '--wordlist',
        type=Path,
        required=True,
        help='Dictionary/wordlist file with keywords to search'
    )
    
    parser.add_argument(
        '--test-regex',
        action='store_true',
        help='Test regex patterns and exit'
    )
    
    args = parser.parse_args()
    
    # Test regex patterns if requested
    if args.test_regex:
        compile_regex_engine()
        return
    
    # Validate input files
    if not args.data.exists():
        print(f" ERROR: Data file does not exist: {args.data}")
        sys.exit(1)
    
    if not args.wordlist.exists():
        print(f" ERROR: Wordlist file does not exist: {args.wordlist}")
        sys.exit(1)
    
    # Initialize and run miner
    miner = DXtaMiner(args.data, args.wordlist)
    
    try:
        miner.load_wordlist()
        miner.process_file()
        miner.print_summary()
        
    except KeyboardInterrupt:
        print("\n  Mining interrupted by user")
        miner.print_summary()
        sys.exit(1)
    except Exception as e:
        print(f" FATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

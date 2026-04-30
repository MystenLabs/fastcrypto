#!/usr/bin/env python3
"""
Script to fetch ALL Sui validators using GraphQL pagination.
"""

import json
import subprocess
import sys
from typing import List, Tuple, Optional

def fetch_all_validators_with_pagination(epoch_id: int = 930) -> List[Tuple[str, int]]:
    """
    Fetch all validators using GraphQL pagination.
    """
    all_validators = []
    has_next_page = True
    after_cursor = None
    
    print(f"🔍 Fetching all validators for epoch {epoch_id}...")
    
    while has_next_page:
        # Build the query with pagination
        if after_cursor:
            query = f"""
            {{
              epoch(epochId: {epoch_id}) {{
                validatorSet {{
                  activeValidators(after: "{after_cursor}") {{
                    pageInfo {{
                      hasNextPage
                      endCursor
                    }}
                    nodes {{
                      name
                      nextEpochStake
                    }}
                  }}
                }}
              }}
            }}
            """
        else:
            query = f"""
            {{
              epoch(epochId: {epoch_id}) {{
                validatorSet {{
                  activeValidators {{
                    pageInfo {{
                      hasNextPage
                      endCursor
                    }}
                    nodes {{
                      name
                      nextEpochStake
                    }}
                  }}
                }}
              }}
            }}
            """
        
        print(f"📡 Fetching page (after: {after_cursor or 'start'})...")
        
        try:
            payload = {
                "query": query,
                "variables": {}
            }
            
            result = subprocess.run([
                'curl', '-s', '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-H', 'Accept: application/json',
                'https://graphql.mainnet.sui.io/graphql',
                '-d', json.dumps(payload)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"❌ Error making request: {result.stderr}")
                break
            
            response = json.loads(result.stdout)
            
            if "errors" in response:
                print(f"❌ GraphQL errors: {response['errors']}")
                break
            
            if "data" not in response:
                print("❌ No data in response")
                break
            
            # Extract validators from this page
            epoch = response["data"]["epoch"]
            validator_set = epoch["validatorSet"]
            active_validators = validator_set["activeValidators"]
            page_info = active_validators["pageInfo"]
            nodes = active_validators["nodes"]
            
            print(f"  📊 Found {len(nodes)} validators on this page")
            
            # Process validators
            for validator in nodes:
                name = validator.get("name", "")
                stake = validator.get("nextEpochStake", 0)
                
                if stake:
                    try:
                        stake_int = int(stake)
                        all_validators.append((name, stake_int))
                        print(f"    ✅ {name}: {stake_int:,} SUI")
                    except ValueError:
                        print(f"    ⚠️  Could not parse stake for {name}: {stake}")
            
            # Update pagination info
            has_next_page = page_info.get("hasNextPage", False)
            after_cursor = page_info.get("endCursor")
            
            print(f"  📄 Has next page: {has_next_page}")
            if after_cursor:
                print(f"  🔄 Next cursor: {after_cursor}")
            
        except Exception as e:
            print(f"❌ Error fetching page: {e}")
            break
    
    print(f"\n🎉 Total validators fetched: {len(all_validators)}")
    return all_validators

def save_to_dat_file(validators: List[Tuple[str, int]], filename: str) -> None:
    """Save validator stakes to a .dat file in descending order."""
    if not validators:
        print("No validator data to save.")
        return
    
    # Sort by stake amount in descending order
    validators.sort(key=lambda x: x[1], reverse=True)
    
    # Extract just the stake amounts
    stakes = [stake for _, stake in validators]
    
    with open(filename, 'w') as f:
        for stake in stakes:
            f.write(f"{stake}\n")
    
    print(f"✅ Saved {len(stakes)} validator stake weights to {filename}")
    print(f"Total stake: {sum(stakes):,}")
    print(f"Largest stake: {stakes[0]:,}")
    print(f"Smallest stake: {stakes[-1]:,}")
    
    # Also save detailed info
    detail_filename = filename.replace('.dat', '_details.txt')
    with open(detail_filename, 'w') as f:
        f.write("Validator Name,Stake Amount\n")
        for name, stake in validators:
            f.write(f"{name},{stake}\n")
    
    print(f"Detailed validator info saved to {detail_filename}")

def test_with_algorithms(filename: str) -> None:
    """Test the generated data with weight reduction algorithms."""
    try:
        print(f"\n🧪 Testing {filename} with weight reduction algorithms...")
        
        result = subprocess.run([
            'cargo', 'run', '--bin', 'solve', '--',
            '--algorithm', 'faster-swiper',
            '--alpha', '1/5',
            '--beta', '1/3', 
            '--weights-path', filename,
            '--show-tickets'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Successfully tested with weight reduction algorithms!")
            print(result.stdout)
        else:
            print("❌ Error testing with algorithms:")
            print(result.stderr)
            
    except Exception as e:
        print(f"❌ Error running algorithms: {e}")

def main():
    """Main function to fetch all Sui validators."""
    print("🚀 Fetching ALL Sui validators using GraphQL pagination...")
    
    # Get current epoch
    try:
        result = subprocess.run([
            'curl', '-s', '-X', 'POST',
            '-H', 'Content-Type: application/json',
            'https://graphql.mainnet.sui.io/graphql',
            '-d', '{"query": "{ epoch { epochId } }"}'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            response = json.loads(result.stdout)
            current_epoch = response["data"]["epoch"]["epochId"]
            print(f"📅 Current epoch: {current_epoch}")
        else:
            current_epoch = 930
            print(f"⚠️  Using default epoch: {current_epoch}")
    except:
        current_epoch = 930
        print(f"⚠️  Using default epoch: {current_epoch}")
    
    # Fetch all validators
    validators = fetch_all_validators_with_pagination(current_epoch)
    
    if validators:
        # Save to .dat file
        output_file = "data/sui_real_all.dat"
        save_to_dat_file(validators, output_file)
        
        # Test with algorithms
        test_with_algorithms(output_file)
        
        print(f"\n🎉 Successfully created complete Sui validator data!")
        print(f"📁 Main file: {output_file}")
        print(f"📁 Details file: {output_file.replace('.dat', '_details.txt')}")
        
    else:
        print("\n❌ Could not fetch validator data.")

if __name__ == "__main__":
    main()

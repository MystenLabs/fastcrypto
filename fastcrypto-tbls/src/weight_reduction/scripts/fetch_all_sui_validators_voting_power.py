#!/usr/bin/env python3
"""
Script to fetch ALL Sui validators' voting power using GraphQL pagination.
"""

import json
import subprocess
from typing import List, Tuple

def fetch_all_validators_with_pagination(epoch_id: int = 930) -> List[Tuple[str, int]]:
    """
    Fetch all validators' voting power using GraphQL pagination.
    """
    all_validators = []
    has_next_page = True
    after_cursor = None
    
    print(f"🔍 Fetching all validators' voting power for epoch {epoch_id}...")
    
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
                      votingPower
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
                      votingPower
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
                voting_power = validator.get("votingPower", 0)
                
                if voting_power:
                    try:
                        voting_power_int = int(voting_power)
                        all_validators.append((name, voting_power_int))
                        print(f"    ✅ {name}: {voting_power_int:,} voting power")
                    except ValueError:
                        print(f"    ⚠️  Could not parse voting power for {name}: {voting_power}")
                else:
                    print(f"    ⚠️  No voting power data for {name}")
            
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
    """Save validator voting power to a .dat file in descending order."""
    if not validators:
        print("No validator data to save.")
        return
    
    # Sort by voting power amount in descending order
    validators.sort(key=lambda x: x[1], reverse=True)
    
    # Extract just the voting power amounts
    voting_powers = [voting_power for _, voting_power in validators]
    
    with open(filename, 'w') as f:
        for voting_power in voting_powers:
            f.write(f"{voting_power}\n")
    
    print(f"✅ Saved {len(voting_powers)} validator voting power weights to {filename}")
    print(f"Total voting power: {sum(voting_powers):,}")
    print(f"Largest voting power: {voting_powers[0]:,}")
    print(f"Smallest voting power: {voting_powers[-1]:,}")
    
    # Also save detailed info
    detail_filename = filename.replace('.dat', '_details.txt')
    with open(detail_filename, 'w') as f:
        f.write("Validator Name,Voting Power\n")
        for name, voting_power in validators:
            f.write(f"{name},{voting_power}\n")
    
    print(f"Detailed validator info saved to {detail_filename}")

def main():
    """Main function to fetch all Sui validators' voting power."""
    import sys
    
    # Get epoch from command line argument or use current epoch
    if len(sys.argv) > 1:
        try:
            epoch = int(sys.argv[1])
            print(f"🚀 Fetching Sui validators' voting power for epoch {epoch}...")
        except ValueError:
            print(f"❌ Invalid epoch: {sys.argv[1]}. Using current epoch instead.")
            epoch = None
    else:
        epoch = None
    
    if epoch is None:
        print("🚀 Fetching ALL Sui validators' voting power using GraphQL pagination...")
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
                epoch = response["data"]["epoch"]["epochId"]
                print(f"📅 Current epoch: {epoch}")
            else:
                epoch = 930
                print(f"⚠️  Using default epoch: {epoch}")
        except:
            epoch = 930
            print(f"⚠️  Using default epoch: {epoch}")
    
    # Fetch all validators
    validators = fetch_all_validators_with_pagination(epoch)
    
    if validators:
        # Save to .dat file with epoch in filename
        if len(sys.argv) > 1:
            output_file = f"data/sui_real_all_voting_power_epoch_{epoch}.dat"
        else:
            output_file = "data/sui_real_all_voting_power.dat"
        save_to_dat_file(validators, output_file)
        
        print(f"\n🎉 Successfully created complete Sui validator voting power data!")
        print(f"📁 Main file: {output_file}")
        print(f"📁 Details file: {output_file.replace('.dat', '_details.txt')}")
        
    else:
        print("\n❌ Could not fetch validator voting power data.")

if __name__ == "__main__":
    main()


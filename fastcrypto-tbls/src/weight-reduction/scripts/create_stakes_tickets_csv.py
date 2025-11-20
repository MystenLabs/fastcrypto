#!/usr/bin/env python3
"""
Script to create a CSV file with stake weights and ticket assignments side by side.
"""

import subprocess
import json
import csv
import sys
from typing import List, Tuple

def get_ticket_assignment(algorithm="faster-swiper", alpha="1/5", beta="1/3", weights_path="data/sui_real_all.dat"):
    """
    Get the ticket assignment from the weight reduction algorithm.
    """
    try:
        # Run the algorithm to get ticket assignment
        result = subprocess.run([
            'cargo', 'run', '--bin', 'solve', '--',
            '--algorithm', algorithm,
            '--alpha', alpha,
            '--beta', beta,
            '--weights-path', weights_path,
            '--show-tickets'
        ], capture_output=True, text=True, timeout=30)
        
        print(f"Running algorithm on: {weights_path}")
        
        if result.returncode != 0:
            print(f"Error running algorithm: {result.stderr}")
            return None
        
        # Parse the output to extract ticket information
        output = result.stdout
        lines = output.strip().split('\n')
        
        # Find the line with ticket information
        ticket_line = None
        for line in lines:
            if 'tickets:' in line:
                ticket_line = line
                break
        
        if not ticket_line:
            print("Could not find ticket information in output")
            return None
        
        # Extract ticket distribution from the line
        # Format: tickets: [[5; 2], [4; 3], [2; 10], [1; 22]]
        print(f"Ticket line: {ticket_line}")
        
        # Find the tickets part more carefully using regex-like approach
        import re
        
        # Look for the pattern: tickets: [[...]]
        match = re.search(r'tickets: (\[\[.*?\]\])', ticket_line)
        if match:
            ticket_part = match.group(1)
            print(f"Ticket part: {ticket_part}")
        else:
            print("Could not find ticket pattern in output")
            return None
        
        # Parse the ticket distribution
        ticket_distribution = []
        
        # Remove outer brackets
        ticket_part = ticket_part.strip('[]')
        if ticket_part:
            # Split by '], [' to get individual ticket groups
            groups = ticket_part.split('], [')
            for group in groups:
                group = group.strip('[]')
                if group:
                    # Parse format like "5; 2" (tickets; count)
                    parts = group.split(';')
                    if len(parts) == 2:
                        try:
                            tickets = int(parts[0].strip())
                            count = int(parts[1].strip())
                            ticket_distribution.append((tickets, count))
                        except ValueError:
                            print(f"Error parsing group: {group}")
                            continue
        
        print(f"Parsed ticket distribution: {ticket_distribution}")
        
        # Verify the ticket distribution matches the number of validators
        total_tickets_from_distribution = sum(tickets * count for tickets, count in ticket_distribution)
        total_validators_with_tickets = sum(count for _, count in ticket_distribution)
        print(f"Total tickets from distribution: {total_tickets_from_distribution}")
        print(f"Total validators with tickets: {total_validators_with_tickets}")
        
        return ticket_distribution
        
    except Exception as e:
        print(f"Error getting ticket assignment: {e}")
        return None

def read_stake_weights(weights_path):
    """
    Read stake weights from the .dat file.
    """
    try:
        with open(weights_path, 'r') as f:
            weights = []
            for line in f:
                line = line.strip()
                if line:
                    weights.append(int(line))
        return weights
    except Exception as e:
        print(f"Error reading weights: {e}")
        return []

def create_ticket_assignment(ticket_distribution, num_validators):
    """
    Create the actual ticket assignment for each validator.
    """
    tickets = [0] * num_validators
    
    current_validator = 0
    for ticket_count, num_validators_with_tickets in ticket_distribution:
        for _ in range(num_validators_with_tickets):
            if current_validator < num_validators:
                tickets[current_validator] = ticket_count
                current_validator += 1
    
    return tickets

def create_csv(stakes, tickets, output_file="sui_stakes_and_tickets.csv"):
    """
    Create a CSV file with stakes and tickets side by side.
    """
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Validator_Index', 'Stake_Weight', 'Ticket_Count', 'Stake_Percentage', 'Ticket_Percentage'])
            
            # Calculate totals
            total_stake = sum(stakes)
            total_tickets = sum(tickets)
            
            # Write data
            for i, (stake, ticket) in enumerate(zip(stakes, tickets)):
                stake_percentage = (stake / total_stake) * 100 if total_stake > 0 else 0
                ticket_percentage = (ticket / total_tickets) * 100 if total_tickets > 0 else 0
                
                writer.writerow([
                    i + 1,  # 1-indexed validator
                    stake,
                    ticket,
                    f"{stake_percentage:.2f}%",
                    f"{ticket_percentage:.2f}%"
                ])
        
        print(f"✅ Created CSV file: {output_file}")
        print(f"   Total validators: {len(stakes)}")
        print(f"   Total stake: {total_stake:,}")
        print(f"   Total tickets: {total_tickets}")
        
        # Show summary statistics
        non_zero_tickets = sum(1 for t in tickets if t > 0)
        print(f"   Validators with tickets: {non_zero_tickets}")
        print(f"   Validators without tickets: {len(stakes) - non_zero_tickets}")
        
        return True
        
    except Exception as e:
        print(f"Error creating CSV: {e}")
        return False

def main():
    """Main function to create the CSV file."""
    print("📊 Creating CSV file with stake weights and ticket assignments...")
    
    # Read stake weights
    weights_path = "data/sui_real_all.dat"
    stakes = read_stake_weights(weights_path)
    
    if not stakes:
        print("❌ Could not read stake weights")
        return
    
    print(f"📈 Read {len(stakes)} validator stake weights")
    
    # Get ticket assignment from algorithm
    ticket_distribution = get_ticket_assignment()
    
    if not ticket_distribution:
        print("❌ Could not get ticket assignment")
        return
    
    print(f"🎫 Ticket distribution: {ticket_distribution}")
    
    # Create actual ticket assignment
    tickets = create_ticket_assignment(ticket_distribution, len(stakes))
    
    # Create CSV file
    if create_csv(stakes, tickets):
        print("\n📋 CSV file created successfully!")
        print("   Columns: Validator_Index, Stake_Weight, Ticket_Count, Stake_Percentage, Ticket_Percentage")
        
        # Show first few rows as preview
        print("\n🔍 Preview of first 10 rows:")
        print("Validator_Index,Stake_Weight,Ticket_Count,Stake_Percentage,Ticket_Percentage")
        for i in range(min(10, len(stakes))):
            stake = stakes[i]
            ticket = tickets[i]
            total_stake = sum(stakes)
            total_tickets = sum(tickets)
            stake_pct = (stake / total_stake) * 100
            ticket_pct = (ticket / total_tickets) * 100 if total_tickets > 0 else 0
            print(f"{i+1},{stake},{ticket},{stake_pct:.2f}%,{ticket_pct:.2f}%")

if __name__ == "__main__":
    main()

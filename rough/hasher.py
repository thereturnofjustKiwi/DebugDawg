"""
CyberSecure Blockchain Threat Logger
=====================================
This script demonstrates how to hash threat log entries and create
an immutable blockchain-based audit trail.

Author: CyberSecure Team
Date: 2025-11-22
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple
import os


class ThreatBlockchain:
    """
    Blockchain implementation for immutable threat logging.
    Each threat detection is stored as a block with cryptographic linking.
    """
    
    def __init__(self):
        self.chain: List[Dict] = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        print("\n🔗 Creating Genesis Block...")
        genesis_block = {
            "block_index": 0,
            "timestamp": datetime.now().isoformat(),
            "flow_metadata": {
                "src_ip": "0.0.0.0",
                "dst_ip": "0.0.0.0",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "GENESIS",
                "flow_id": "GENESIS_BLOCK"
            },
            "classification": {
                "prediction": "GENESIS",
                "attack_type": "N/A",
                "confidence_score": 1.0
            },
            "security_action": {
                "action": "Chain Initialization",
                "priority": "INFO",
                "auto_executed": True,
                "execution_timestamp": datetime.now().isoformat()
            },
            "previous_hash": "0" * 64
        }
        
        genesis_block["current_hash"] = self.calculate_hash(genesis_block)
        self.chain.append(genesis_block)
        print(f"✅ Genesis Block Created: {genesis_block['current_hash'][:16]}...")
    
    def calculate_hash(self, block: Dict) -> str:
        """
        Calculate SHA-256 hash of block data.
        
        Args:
            block: Block dictionary containing threat log data
            
        Returns:
            64-character hexadecimal hash string
        """
        # Extract only the fields that should be hashed (exclude current_hash)
        hashable_block = {
            "block_index": block["block_index"],
            "timestamp": block["timestamp"],
            "flow_metadata": block["flow_metadata"],
            "classification": block["classification"],
            "security_action": block["security_action"],
            "previous_hash": block["previous_hash"]
        }
        
        # Add network_features if present (for full log entries)
        if "network_features" in block:
            hashable_block["network_features"] = block["network_features"]
        
        # Convert to JSON string with sorted keys for consistency
        block_string = json.dumps(hashable_block, sort_keys=True)
        
        # Calculate SHA-256 hash
        hash_object = hashlib.sha256(block_string.encode('utf-8'))
        return hash_object.hexdigest()
    
    def add_block_from_json(self, json_file_path: str) -> Dict:
        """
        Load a threat log from JSON file and add to blockchain.
        
        Args:
            json_file_path: Path to JSON file containing threat log
            
        Returns:
            The created block dictionary
        """
        print(f"\n📄 Loading threat log from: {json_file_path}")
        
        # Load JSON file
        with open(json_file_path, 'r') as f:
            threat_log = json.load(f)
        
        print(f"✅ Loaded log entry: {threat_log['log_id']}")
        print(f"   Attack Type: {threat_log['classification']['attack_type']}")
        print(f"   Confidence: {threat_log['classification']['confidence_score']}")
        print(f"   Action: {threat_log['security_action']['action']}")
        
        # Get previous block
        previous_block = self.chain[-1]
        
        # Create new block
        new_block = {
            "block_index": len(self.chain),
            "timestamp": threat_log["timestamp"],
            "flow_metadata": threat_log["flow_metadata"],
            "classification": threat_log["classification"],
            "security_action": threat_log["security_action"],
            "network_features": threat_log.get("network_features", {}),
            "log_id": threat_log.get("log_id", f"TL-{len(self.chain)}"),
            "previous_hash": previous_block["current_hash"]
        }
        
        # Calculate hash
        print("\n🔐 Calculating SHA-256 hash...")
        new_block["current_hash"] = self.calculate_hash(new_block)
        
        # Add to chain
        self.chain.append(new_block)
        
        print(f"✅ Block #{new_block['block_index']} added to blockchain")
        print(f"   Current Hash:  {new_block['current_hash']}")
        print(f"   Previous Hash: {new_block['previous_hash'][:32]}...")
        
        return new_block
    
    def add_block_direct(self, threat_data: Dict) -> Dict:
        """
        Add a block directly from a dictionary.
        
        Args:
            threat_data: Dictionary containing threat log data
            
        Returns:
            The created block dictionary
        """
        previous_block = self.chain[-1]
        
        new_block = {
            "block_index": len(self.chain),
            "timestamp": threat_data.get("timestamp", datetime.now().isoformat()),
            "flow_metadata": threat_data["flow_metadata"],
            "classification": threat_data["classification"],
            "security_action": threat_data["security_action"],
            "network_features": threat_data.get("network_features", {}),
            "log_id": threat_data.get("log_id", f"TL-{len(self.chain)}"),
            "previous_hash": previous_block["current_hash"]
        }
        
        new_block["current_hash"] = self.calculate_hash(new_block)
        self.chain.append(new_block)
        
        return new_block
    
    def verify_chain(self) -> Tuple[bool, str]:
        """
        Verify the integrity of the entire blockchain.
        
        Returns:
            Tuple of (is_valid, message)
        """
        print("\n🔍 Verifying blockchain integrity...")
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check 1: Verify current block's hash is correct
            recalculated_hash = self.calculate_hash(current_block)
            if current_block["current_hash"] != recalculated_hash:
                error_msg = f"❌ Block {i} hash mismatch! Data has been tampered with!"
                print(error_msg)
                print(f"   Expected: {current_block['current_hash']}")
                print(f"   Calculated: {recalculated_hash}")
                return False, error_msg
            
            # Check 2: Verify link to previous block
            if current_block["previous_hash"] != previous_block["current_hash"]:
                error_msg = f"❌ Block {i} chain broken! Previous hash doesn't match!"
                print(error_msg)
                return False, error_msg
            
            print(f"   ✓ Block {i} verified")
        
        success_msg = f"✅ Blockchain integrity verified! All {len(self.chain)} blocks are valid."
        print(f"\n{success_msg}")
        return True, success_msg
    
    def export_chain(self, filename: str = "blockchain_audit_trail.json"):
        """Export the entire blockchain to JSON file"""
        print(f"\n💾 Exporting blockchain to: {filename}")
        
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=2)
        
        file_size = os.path.getsize(filename) / 1024  # KB
        print(f"✅ Exported {len(self.chain)} blocks ({file_size:.2f} KB)")
    
    def display_block(self, block_index: int):
        """Display detailed information about a specific block"""
        if 0 <= block_index < len(self.chain):
            block = self.chain[block_index]
            
            print(f"\n{'='*70}")
            print(f"BLOCK #{block['block_index']}")
            print(f"{'='*70}")
            print(f"Timestamp: {block['timestamp']}")
            print(f"Current Hash:  {block['current_hash']}")
            print(f"Previous Hash: {block['previous_hash']}")
            print(f"\nFlow Metadata:")
            print(f"  Source: {block['flow_metadata']['src_ip']}:{block['flow_metadata']['src_port']}")
            print(f"  Destination: {block['flow_metadata']['dst_ip']}:{block['flow_metadata']['dst_port']}")
            print(f"  Protocol: {block['flow_metadata']['protocol']}")
            print(f"\nClassification:")
            print(f"  Prediction: {block['classification']['prediction']}")
            print(f"  Attack Type: {block['classification']['attack_type']}")
            print(f"  Confidence: {block['classification']['confidence_score']}")
            print(f"\nSecurity Action:")
            print(f"  Action: {block['security_action']['action']}")
            print(f"  Priority: {block['security_action']['priority']}")
            print(f"  Auto-executed: {block['security_action']['auto_executed']}")
            
            if "network_features" in block and block["network_features"]:
                print(f"\nNetwork Features:")
                for key, value in block['network_features'].items():
                    print(f"  {key}: {value}")
            
            print(f"{'='*70}\n")
        else:
            print(f"❌ Block {block_index} not found!")
    
    def get_chain_summary(self) -> Dict:
        """Get summary statistics of the blockchain"""
        if len(self.chain) <= 1:
            return {
                "total_blocks": len(self.chain),
                "total_threats": 0,
                "attack_types": {},
                "priority_distribution": {}
            }
        
        threats = self.chain[1:]  # Exclude genesis block
        
        summary = {
            "total_blocks": len(self.chain),
            "total_threats": len(threats),
            "attack_types": {},
            "priority_distribution": {},
            "auto_executed_count": 0
        }
        
        for block in threats:
            attack_type = block["classification"]["attack_type"]
            priority = block["security_action"]["priority"]
            
            summary["attack_types"][attack_type] = summary["attack_types"].get(attack_type, 0) + 1
            summary["priority_distribution"][priority] = summary["priority_distribution"].get(priority, 0) + 1
            
            if block["security_action"]["auto_executed"]:
                summary["auto_executed_count"] += 1
        
        return summary
    
    def demonstrate_tampering_detection(self):
        """Demonstrate how tampering is detected"""
        print("\n" + "="*70)
        print("TAMPERING DETECTION DEMONSTRATION")
        print("="*70)
        
        if len(self.chain) < 2:
            print("❌ Need at least one threat block to demonstrate tampering")
            return
        
        # Show original state
        print("\n📊 Original Blockchain State:")
        self.verify_chain()
        
        # Simulate tampering
        print("\n⚠️  SIMULATING TAMPERING: Modifying attack type in Block 1...")
        original_attack_type = self.chain[1]["classification"]["attack_type"]
        self.chain[1]["classification"]["attack_type"] = "MODIFIED_ATTACK"
        print(f"   Changed '{original_attack_type}' → 'MODIFIED_ATTACK'")
        
        # Verify again (should fail)
        print("\n🔍 Verifying tampered blockchain...")
        is_valid, message = self.verify_chain()
        
        # Restore original
        print("\n🔄 Restoring original data...")
        self.chain[1]["classification"]["attack_type"] = original_attack_type
        print("   Data restored")
        
        # Verify again (should pass)
        print("\n🔍 Verifying restored blockchain...")
        self.verify_chain()


def main():
    """Main execution function"""
    print("\n" + "="*70)
    print("🛡️  CYBERSECURE BLOCKCHAIN THREAT LOGGER")
    print("="*70)
    
    # Initialize blockchain
    blockchain = ThreatBlockchain()
    
    # Add threat log from JSON file
    try:
        blockchain.add_block_from_json("log.json")
    except FileNotFoundError:
        print("\n❌ Error: sample_threat_log.json not found!")
        print("   Please ensure the JSON file is in the same directory.")
        return
    
    # Add a few more sample threats directly
    print("\n" + "="*70)
    print("📝 Adding additional threat logs...")
    print("="*70)
    
    # Threat 2: Port Scan
    blockchain.add_block_direct({
        "log_id": "TL-2025112211580002",
        "timestamp": "2025-11-22T11:59:15.456789",
        "flow_metadata": {
            "src_ip": "10.0.0.23",
            "dst_ip": "192.168.1.1",
            "src_port": 12345,
            "dst_port": 22,
            "protocol": "TCP",
            "flow_id": "10.0.0.23:12345->192.168.1.1:22"
        },
        "classification": {
            "prediction": "INTRUSION",
            "attack_type": "Port Scan",
            "confidence_score": 0.893
        },
        "security_action": {
            "action": "Enable Enhanced Logging + Monitor",
            "priority": "HIGH",
            "auto_executed": True,
            "execution_timestamp": "2025-11-22T11:59:16.000000"
        },
        "network_features": {
            "destination_port": 22,
            "flow_duration": 5432,
            "total_fwd_packets": 89,
            "flow_bytes_per_sec": 2134.7,
            "flow_packets_per_sec": 45.2
        }
    })
    print("✅ Block #2 added (Port Scan)")
    
    # Threat 3: Web Attack
    blockchain.add_block_direct({
        "log_id": "TL-2025112211580003",
        "timestamp": "2025-11-22T12:00:45.789012",
        "flow_metadata": {
            "src_ip": "172.16.0.50",
            "dst_ip": "203.0.113.100",
            "src_port": 48921,
            "dst_port": 443,
            "protocol": "TCP",
            "flow_id": "172.16.0.50:48921->203.0.113.100:443"
        },
        "classification": {
            "prediction": "INTRUSION",
            "attack_type": "Web Attack",
            "confidence_score": 0.941
        },
        "security_action": {
            "action": "Quarantine Endpoint + Alert SOC",
            "priority": "CRITICAL",
            "auto_executed": True,
            "execution_timestamp": "2025-11-22T12:00:46.000000"
        },
        "network_features": {
            "destination_port": 443,
            "flow_duration": 89765,
            "total_fwd_packets": 234,
            "flow_bytes_per_sec": 18945.3,
            "flow_packets_per_sec": 67.8
        }
    })
    print("✅ Block #3 added (Web Attack)")
    
    # Display all blocks
    print("\n" + "="*70)
    print("📋 BLOCKCHAIN CONTENTS")
    print("="*70)
    
    for i in range(len(blockchain.chain)):
        blockchain.display_block(i)
    
    # Verify chain integrity
    blockchain.verify_chain()
    
    # Display summary
    summary = blockchain.get_chain_summary()
    print("\n" + "="*70)
    print("📊 BLOCKCHAIN SUMMARY")
    print("="*70)
    print(f"Total Blocks: {summary['total_blocks']}")
    print(f"Total Threats: {summary['total_threats']}")
    print(f"Auto-executed Actions: {summary['auto_executed_count']}")
    print(f"\nAttack Types Distribution:")
    for attack_type, count in summary['attack_types'].items():
        print(f"  • {attack_type}: {count}")
    print(f"\nPriority Distribution:")
    for priority, count in summary['priority_distribution'].items():
        print(f"  • {priority}: {count}")
    
    # Export blockchain
    blockchain.export_chain()
    
    # Demonstrate tampering detection
    blockchain.demonstrate_tampering_detection()
    
    print("\n" + "="*70)
    print("✅ DEMONSTRATION COMPLETE")
    print("="*70)
    print("\nFiles created:")
    print("  • blockchain_audit_trail.json - Complete blockchain export")
    print("\nKey features demonstrated:")
    print("  ✓ Loading threat logs from JSON")
    print("  ✓ SHA-256 cryptographic hashing")
    print("  ✓ Blockchain chaining and linking")
    print("  ✓ Integrity verification")
    print("  ✓ Tampering detection")
    print("  ✓ Audit trail export")
    print("\n")


if __name__ == "__main__":
    main()

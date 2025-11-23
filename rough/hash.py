import hashlib
import json
from datetime import datetime

class ThreatBlockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
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
            "previous_hash": "0" * 64  # 64 zeros for genesis block
        }
        
        genesis_block["current_hash"] = self.calculate_hash(genesis_block)
        self.chain.append(genesis_block)
    
    def calculate_hash(self, block):
        """
        Calculate SHA-256 hash of block data
        
        CRITICAL: Only hash the fields that define the block's identity.
        DO NOT include the current_hash field itself.
        """
        # Create a copy without the current_hash field
        hashable_block = {
            "block_index": block["block_index"],
            "timestamp": block["timestamp"],
            "flow_metadata": block["flow_metadata"],
            "classification": block["classification"],
            "security_action": block["security_action"],
            "previous_hash": block["previous_hash"]
        }
        
        # Convert to JSON string with sorted keys for consistency
        block_string = json.dumps(hashable_block, sort_keys=True)
        
        # Calculate SHA-256 hash
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()
    
    def add_threat_block(self, src_ip, dst_ip, src_port, dst_port, protocol,
                        prediction, attack_type, confidence_score,
                        action, priority, auto_executed):
        """
        Add a new threat detection to the blockchain
        """
        timestamp = datetime.now().isoformat()
        previous_block = self.chain[-1]
        
        new_block = {
            "block_index": len(self.chain),
            "timestamp": timestamp,
            "flow_metadata": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "flow_id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            },
            "classification": {
                "prediction": prediction,
                "attack_type": attack_type,
                "confidence_score": round(confidence_score, 3)
            },
            "security_action": {
                "action": action,
                "priority": priority,
                "auto_executed": auto_executed,
                "execution_timestamp": timestamp
            },
            "previous_hash": previous_block["current_hash"]
        }
        
        # Calculate hash for this block
        new_block["current_hash"] = self.calculate_hash(new_block)
        
        # Add to chain
        self.chain.append(new_block)
        
        return new_block
    
    def verify_chain(self):
        """
        Verify the integrity of the entire blockchain
        Returns: (is_valid, error_message)
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check 1: Verify current block's hash is correct
            recalculated_hash = self.calculate_hash(current_block)
            if current_block["current_hash"] != recalculated_hash:
                return False, f"Block {i} hash mismatch. Data has been tampered!"
            
            # Check 2: Verify link to previous block
            if current_block["previous_hash"] != previous_block["current_hash"]:
                return False, f"Block {i} previous_hash doesn't match Block {i-1} hash. Chain broken!"
        
        return True, "Blockchain integrity verified ✓"
    
    def export_chain(self, filename="blockchain_audit_trail.json"):
        """Export the entire blockchain to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=2)
        print(f"✅ Blockchain exported to {filename}")
    
    def get_block_by_index(self, index):
        """Retrieve a specific block by index"""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_threat_summary(self):
        """Get summary statistics from the blockchain"""
        if len(self.chain) <= 1:  # Only genesis block
            return {"total_threats": 0}
        
        threats = self.chain[1:]  # Exclude genesis block
        
        summary = {
            "total_threats": len(threats),
            "attack_types": {},
            "priority_distribution": {},
            "auto_executed_count": sum(1 for b in threats if b["security_action"]["auto_executed"])
        }
        
        for block in threats:
            attack_type = block["classification"]["attack_type"]
            priority = block["security_action"]["priority"]
            
            summary["attack_types"][attack_type] = summary["attack_types"].get(attack_type, 0) + 1
            summary["priority_distribution"][priority] = summary["priority_distribution"].get(priority, 0) + 1
        
        return summary

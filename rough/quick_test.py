"""
Quick Test Script - Verify Blockchain Implementation
======================================================
This script provides a minimal example of loading a JSON log
and hashing it via blockchain.
"""

import json
import hashlib

# Simple standalone function to hash a JSON log
def hash_json_log(json_file_path):
    """
    Load JSON log and calculate SHA-256 hash
    
    Args:
        json_file_path: Path to JSON threat log file
        
    Returns:
        tuple: (original_data, hash_value)
    """
    print(f"\n📄 Loading: {json_file_path}")
    
    # Load JSON
    with open(json_file_path, 'r') as f:
        log_data = json.load(f)
    
    print(f"✅ Loaded log ID: {log_data.get('log_id', 'N/A')}")
    print(f"   Attack Type: {log_data['classification']['attack_type']}")
    print(f"   Confidence: {log_data['classification']['confidence_score']}")
    
    # Extract hashable fields
    hashable_data = {
        "timestamp": log_data["timestamp"],
        "flow_metadata": log_data["flow_metadata"],
        "classification": log_data["classification"],
        "security_action": log_data["security_action"]
    }
    
    # Convert to JSON string (sorted keys for consistency)
    json_string = json.dumps(hashable_data, sort_keys=True)
    
    print(f"\n🔐 Data to be hashed:")
    print(f"   {json_string[:100]}...")
    
    # Calculate SHA-256 hash
    hash_object = hashlib.sha256(json_string.encode('utf-8'))
    hash_value = hash_object.hexdigest()
    
    print(f"\n✅ SHA-256 Hash:")
    print(f"   {hash_value}")
    print(f"\n   Length: {len(hash_value)} characters")
    print(f"   First 16 chars: {hash_value[:16]}")
    print(f"   Last 16 chars: {hash_value[-16:]}")
    
    return log_data, hash_value


if __name__ == "__main__":
    print("="*70)
    print("SIMPLE JSON LOG HASHER")
    print("="*70)
    
    try:
        # Hash the sample log
        data, hash_val = hash_json_log("log.json")
        
        print("\n" + "="*70)
        print("✅ SUCCESS: JSON log successfully hashed!")
        print("="*70)
        
        print("\nYou can now:")
        print("  1. Run the full blockchain demo: python blockchain_hasher.py")
        print("  2. Use this hash value to verify data integrity")
        print("  3. Chain multiple logs together")
        
    except FileNotFoundError:
        print("\n❌ Error: sample_threat_log.json not found!")
        print("   Make sure the JSON file is in the same directory.")
    except KeyError as e:
        print(f"\n❌ Error: Missing required field in JSON: {e}")
    except json.JSONDecodeError:
        print("\n❌ Error: Invalid JSON format!")
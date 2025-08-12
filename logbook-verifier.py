#!/usr/bin/env python3
"""
logbook-verifier 1.1 - Frankenwatch logbook signature and file hash verification utility
"""

import argparse
import json
import base64
import sys
import hashlib
import urllib.request
import urllib.parse
from datetime import datetime, date

# Check for required dependencies with nice error message
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("❌ Error: Missing required 'cryptography' module")
    print("")
    print("🔧 To install the missing dependency:")
    print("   python3 -m venv venv")
    print("   source venv/bin/activate")
    print("   pip3 install cryptography")
    print("")
    print("💡 Then run the logbook verifier again from within the virtual environment.")
    sys.exit(1)


def base64url_decode(base64url_string):
    """Decode a Base64URL string to bytes."""
    # Add padding back
    padding = 4 - len(base64url_string) % 4
    if padding != 4:
        base64url_string += '=' * padding
    
    # Replace URL-safe characters with standard Base64 characters
    base64_string = base64url_string.replace('-', '+').replace('_', '/')
    
    return base64.b64decode(base64_string)


def load_keyfile(keyfile_path):
    """Load and parse the keyfile JSON."""
    try:
        with open(keyfile_path, 'r') as f:
            keydata = json.load(f)
        
        # Decode the Base64URL encoded keys
        public_key_b64url = keydata['public_key']
        private_key_b64url = keydata['private_key']
        
        public_key_bytes = base64url_decode(public_key_b64url)
        private_key_bytes = base64url_decode(private_key_b64url)
        
        # Try to load as raw Ed25519 keys first
        try:
            if len(public_key_bytes) == 32:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            else:
                # Try as DER-encoded public key
                public_key = serialization.load_der_public_key(public_key_bytes)
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise ValueError("Public key is not Ed25519")
        except Exception as e:
            print(f"[error] Failed to load public key: {e}")
            sys.exit(1)
            
        try:
            if len(private_key_bytes) == 32:
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            else:
                # Try as DER-encoded private key (PKCS#8)
                private_key = serialization.load_der_private_key(
                    private_key_bytes, 
                    password=None
                )
                if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                    raise ValueError("Private key is not Ed25519")
        except Exception as e:
            print(f"[error] Failed to load private key: {e}")
            sys.exit(1)
        
        return public_key, private_key
        
    except FileNotFoundError:
        print(f"[error] Keyfile not found: {keyfile_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[error] Invalid JSON in keyfile: {keyfile_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[error] Failed to load keys: {e}")
        sys.exit(1)


def load_logbook(logbook_path):
    """Load and parse the logbook JSON."""
    try:
        with open(logbook_path, 'r') as f:
            logbook = json.load(f)
        return logbook
        
    except FileNotFoundError:
        print(f"[error] Logbook not found: {logbook_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[error] Invalid JSON in logbook: {logbook_path}")
        sys.exit(1)


def create_message_to_verify(event_data):
    """Create the message that was signed from event_data."""
    
    # Check if this is a photo upload, thumbnail upload, or property update event
    if 'photo_type' in event_data or 'thumbnail_type' in event_data:
        # Both photo and thumbnail upload events use the same signature structure
        if 'photo_type' in event_data:
            sub_type_value = event_data.get('photo_type')
        else:
            sub_type_value = event_data.get('thumbnail_type')
            
        payload = {
            'sub_type': sub_type_value,  # photo_type or thumbnail_type maps to sub_type in signature
            'note': event_data.get('note', ''),
            'file_size': event_data.get('file_size'),
            'file_type': event_data.get('mime_type'),  # Note: mime_type maps to file_type in signature
            'file_hash': event_data.get('file_hash'),
            'timestamp': event_data.get('timestamp')
        }
        
        # For thumbnail events, check if original_file_id exists in event data
        if 'thumbnail_type' in event_data:
            if 'original_file_id' in event_data:
                # Rebuild payload with original_file_id in correct position
                payload = {
                    'sub_type': sub_type_value,
                    'note': event_data.get('note', ''),
                    'file_size': event_data.get('file_size'),
                    'file_type': event_data.get('mime_type'),
                    'file_hash': event_data.get('file_hash'),
                    'original_file_id': event_data.get('original_file_id'),
                    'timestamp': event_data.get('timestamp')
                }
            # If original_file_id not in event data, don't add it to signature payload
            # This happens because server uses original_file_id for signing but doesn't store it
    else:
        # Property update events are wrapped in {"event": event_data}
        payload = {"event": event_data}
    
    # Don't sort keys to match JavaScript JSON.stringify behavior
    return json.dumps(payload, separators=(',', ':')).encode('utf-8')


def download_and_verify_file_hash(event_data, public_key):
    """Download image file and verify its hash matches the recorded hash."""
    try:
        file_id = event_data.get('file_id')
        recorded_hash = event_data.get('file_hash')
        
        if not file_id or not recorded_hash:
            return False, "Missing file_id or file_hash"
        
        # Construct download URL - add ?thumbnail parameter for thumbnail events
        if 'thumbnail_type' in event_data:
            download_url = f"https://api.frankenwatch.xyz/api/v1/info/files/{file_id}?thumbnail"
        else:
            download_url = f"https://api.frankenwatch.xyz/api/v1/info/files/{file_id}"
        
        # Download the file with proper headers
        try:
            # Create request with proper User-Agent header
            request = urllib.request.Request(
                download_url,
                headers={
                    'User-Agent': 'FrankenWatch-Logbook-Verifier/1.1 (Python urllib)',
                    'Accept': 'image/webp,image/png,image/jpeg,*/*'
                }
            )
            
            with urllib.request.urlopen(request) as response:
                file_data = response.read()
        except urllib.error.HTTPError as e:
            return False, f"Download failed: HTTP {e.code}"
        except urllib.error.URLError as e:
            if "nodename nor servname provided" in str(e) or "Name or service not known" in str(e):
                return False, "Network unavailable (no internet connection)"
            else:
                return False, f"Network error: {str(e)}"
        except Exception as e:
            return False, f"Download failed: {str(e)}"
        
        # Calculate SHA-256 hash
        calculated_hash = hashlib.sha256(file_data).hexdigest()
        calculated_hash_with_prefix = f"sha256:{calculated_hash}"
        
        # Compare hashes
        if calculated_hash_with_prefix == recorded_hash:
            return True, f"Hash verified: {calculated_hash_with_prefix}"
        else:
            return False, f"Hash mismatch: recorded={recorded_hash}, calculated={calculated_hash_with_prefix}"
            
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def verify_event_signature(event, public_key):
    """Verify the signature of a single event."""
    try:
        # Get the signature and decode it (signatures are also Base64URL now)
        signature_b64url = event['signature']
        signature_bytes = base64url_decode(signature_b64url)
        
        # Create the message that was signed
        message = create_message_to_verify(event['event_data'])
        
        # Verify the signature
        public_key.verify(signature_bytes, message)
        return True
        
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Frankenwatch logbook signature and file hash verification utility"
    )
    parser.add_argument('--keyfile', required=True, help='Path to the keyfile JSON')
    parser.add_argument('--logbook', required=True, help='Path to the logbook JSON')
    parser.add_argument('--offline', action='store_true',
                       help='Skip file hash verification (no file downloads)')
    
    args = parser.parse_args()
    
    print("logbook-verifier 1.1 - Frankenwatch logbook signature and file hash verification utility")
    
    # Load keys
    public_key, private_key = load_keyfile(args.keyfile)
    
    # Load logbook
    logbook = load_logbook(args.logbook)
    
    if not logbook.get('success', False):
        print("[error] Logbook indicates failure status")
        sys.exit(1)
    
    events = logbook.get('data', {}).get('events', [])
    total_events = len(events)
    valid_count = 0
    invalid_count = 0
    warning_count = 0
    
    # Statistics tracking
    property_updates = {}  # property name -> count
    file_events_by_type = {}  # image/thumbnail type -> count
    failed_events = []  # list of failed event details
    event_timestamps = []  # list of event timestamps for time analysis
    event_dates = set()  # unique dates when events occurred
    
    # Get the public key string for file downloads
    public_key_data = logbook.get('data', {}).get('public_key', '')
    
    # Verify each event
    for event in events:
        event_id = event.get('id', 'unknown')
        created_at = event.get('created_at', 'unknown')
        event_data = event.get('event_data', {})
        
        # Collect timestamp data for time analysis
        if created_at != 'unknown':
            try:
                # Parse timestamp and extract date
                event_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                event_timestamps.append(event_dt)
                event_dates.add(event_dt.date())
            except ValueError:
                # Handle different timestamp formats
                try:
                    event_dt = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
                    event_timestamps.append(event_dt)
                    event_dates.add(event_dt.date())
                except ValueError:
                    pass  # Skip unparseable timestamps
        
        # Verify signature
        is_signature_valid = verify_event_signature(event, public_key)
        
        # Determine event type and details
        is_file_event = ('photo_type' in event_data or 'thumbnail_type' in event_data) and 'file_id' in event_data
        
        if is_file_event:
            # Image or thumbnail upload event
            if 'photo_type' in event_data:
                photo_type = event_data.get('photo_type', 'unknown')
                event_description = f"(image: {photo_type})"
                file_events_by_type[f"image:{photo_type}"] = file_events_by_type.get(f"image:{photo_type}", 0) + 1
            else:
                thumbnail_type = event_data.get('thumbnail_type', 'unknown')
                event_description = f"(thumbnail: {thumbnail_type})"
                file_events_by_type[f"thumbnail:{thumbnail_type}"] = file_events_by_type.get(f"thumbnail:{thumbnail_type}", 0) + 1
        else:
            # Property update event - list the properties being updated
            # Exclude timestamp as it's always present
            properties = [key for key in event_data.keys() if key != 'timestamp']
            if properties:
                props_str = ', '.join(sorted(properties))
                event_description = f"(property: {props_str})"
                # Count individual properties
                for prop in properties:
                    property_updates[prop] = property_updates.get(prop, 0) + 1
            else:
                event_description = "(property: none)"
        
        # First level: Signature verification
        if is_signature_valid:
            print(f"[✅] {created_at}:event id#{event_id} {event_description}: signature valid")
            
            # Second level: File hash verification (only for file events)
            if is_file_event:
                if args.offline:
                    print(f"     [⚠️ ] Download image: skipped (offline mode)")
                    warning_count += 1
                else:
                    # Attempt file hash verification
                    hash_valid, hash_message = download_and_verify_file_hash(event_data, public_key_data)
                    if hash_valid:
                        print(f"     [✅] Download image: OK. File hash: OK.")
                    else:
                        # Check if it's a network error vs hash mismatch
                        if "Network unavailable" in hash_message or "network" in hash_message.lower():
                            print(f"     [⚠️ ] Download image: failed: {hash_message}")
                            warning_count += 1
                        elif "Hash mismatch" in hash_message:
                            # Extract the hashes for cleaner display
                            if "recorded=" in hash_message and "calculated=" in hash_message:
                                parts = hash_message.split(", ")
                                recorded = parts[0].replace("Hash mismatch: recorded=", "")
                                calculated = parts[1].replace("calculated=", "")
                                print(f"     [❌] Download image: OK. File hash: ERROR: NO MATCH:")
                                print(f"          Expected: {recorded}")
                                print(f"          Got:      {calculated}")
                            else:
                                print(f"     [❌] Download image: OK. File hash: ERROR: {hash_message}")
                            # Track as failed event
                            failed_events.append({
                                'id': event_id,
                                'created_at': created_at,
                                'description': event_description,
                                'reason': 'File hash mismatch',
                                'details': hash_message
                            })
                        else:
                            print(f"     [⚠️ ] Download image: failed: {hash_message}")
                            warning_count += 1
            
            valid_count += 1
        else:
            print(f"[❌] {created_at}:event id#{event_id} {event_description}: signature INVALID")
            
            # Track as failed event
            failed_events.append({
                'id': event_id,
                'created_at': created_at,
                'description': event_description,
                'reason': 'Invalid cryptographic signature',
                'details': 'Event signature could not be verified with provided public key'
            })
            
            # For invalid signatures, don't attempt file verification
            if is_file_event:
                print(f"     [⚠️ ] Download image: skipped (signature verification failed)")
                warning_count += 1
            
            invalid_count += 1
    
    # Comprehensive Summary
    print("\n" + "="*60)
    print("LOGBOOK VERIFICATION ANALYSIS SUMMARY")
    print("="*60)
    
    # Event counts
    print(f"\n📊 EVENT STATISTICS:")
    print(f"   Total events processed: {total_events}")
    print(f"   Property updates: {len([e for e in events if not (('photo_type' in e.get('event_data', {}) or 'thumbnail_type' in e.get('event_data', {})) and 'file_id' in e.get('event_data', {}))])}")
    print(f"   File uploads (images/thumbnails): {len([e for e in events if ('photo_type' in e.get('event_data', {}) or 'thumbnail_type' in e.get('event_data', {})) and 'file_id' in e.get('event_data', {})])}")
    
    # Property breakdown
    if property_updates:
        print(f"\n📝 PROPERTY UPDATE BREAKDOWN:")
        for prop, count in sorted(property_updates.items()):
            print(f"   {prop}: {count} update{'s' if count != 1 else ''}")
    
    # File event breakdown
    if file_events_by_type:
        print(f"\n📁 FILE UPLOAD BREAKDOWN:")
        for file_type, count in sorted(file_events_by_type.items()):
            print(f"   {file_type}: {count} upload{'s' if count != 1 else ''}")
    
    # Time analysis
    if event_timestamps:
        print(f"\n⏰ TIME ANALYSIS:")
        
        # Calculate time spans
        event_timestamps.sort()
        oldest_event = event_timestamps[0]
        newest_event = event_timestamps[-1]
        today = datetime.now().date()
        
        days_since_oldest = (today - oldest_event.date()).days
        days_since_newest = (today - newest_event.date()).days
        span_days = (newest_event.date() - oldest_event.date()).days
        active_days = len(event_dates)
        
        print(f"   Oldest event: {oldest_event.strftime('%Y-%m-%d %H:%M:%S')} ({days_since_oldest} days ago)")
        print(f"   Newest event: {newest_event.strftime('%Y-%m-%d %H:%M:%S')} ({days_since_newest} days ago)")
        print(f"   Activity span: {span_days} days")
        print(f"   Active days: {active_days} days (days with events)")
        
        if span_days > 0:
            activity_rate = (active_days / (span_days + 1)) * 100
            print(f"   Activity rate: {activity_rate:.1f}% (percentage of days with events)")
    
    # Verification results
    print(f"\n✅ VERIFICATION RESULTS:")
    print(f"   Passed: {valid_count} events (cryptographic signatures verified)")
    print(f"   Failed: {invalid_count} events (invalid signatures - possible tampering)")
    print(f"   Warnings: {warning_count} items (file downloads skipped/failed)")
    
    # Failed events detail
    if failed_events:
        print(f"\n❌ FAILED EVENTS DETAILS:")
        for failed in failed_events:
            print(f"   Event #{failed['id']} ({failed['created_at']}) {failed['description']}")
            print(f"      Reason: {failed['reason']}")
            if failed['details'] != failed['reason']:
                print(f"      Details: {failed['details']}")
    
    # Overall status
    print(f"\n🎯 OVERALL STATUS:")
    if invalid_count == 0:
        if warning_count == 0:
            print("   ✅ ALL EVENTS VERIFIED SUCCESSFULLY")
            print("   🔒 Logbook integrity confirmed - all signatures valid")
        else:
            print(f"   ✅ ALL EVENTS VERIFIED (with {warning_count} file download warnings)")
            print("   🔒 Logbook integrity confirmed - all signatures valid")
            if args.offline:
                print("   ⚠️  Some file hashes could not be verified (offline mode)")
            else:
                print("   ⚠️  Some file hashes could not be verified due to download issues")
    else:
        print(f"   ❌ VERIFICATION FAILED - {invalid_count} events have invalid signatures")
        print("   🚨 Logbook integrity compromised - some events may be tampered with")
        if warning_count > 0:
            print(f"   ⚠️  Additionally, {warning_count} file downloads were skipped/failed")
    
    print("="*60)
    
    # Exit with error code if any signatures were invalid
    if invalid_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

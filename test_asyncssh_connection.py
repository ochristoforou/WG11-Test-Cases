#!/usr/bin/env python3
"""
Simple test script to verify asyncssh connection with SSH certificates
"""

import asyncio
import asyncssh
import sys
import json

async def test_connection(config_file):
    """Test SSH connection using asyncssh"""
    try:
        # Load config
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        print(f"Testing connection to {config['target_host']}:{config['target_port']}")
        print(f"Username: {config['ssh_username']}")
        print(f"Private key: {config['ssh_private_key_path']}")
        if config.get('ssh_certificate_path'):
            print(f"Certificate: {config['ssh_certificate_path']}")
        
        # Prepare connection parameters
        connect_kwargs = {
            'host': config['target_host'],
            'port': config['target_port'],
            'username': config['ssh_username'],
            'known_hosts': None,  # Disable host key checking for testing
            'login_timeout': 30
        }
        
        # Add authentication
        if config.get('ssh_private_key_path'):
            connect_kwargs['client_keys'] = [config['ssh_private_key_path']]
            if config.get('ssh_private_key_passphrase'):
                connect_kwargs['passphrase'] = config['ssh_private_key_passphrase']
            print("Using key-based authentication")
        elif config.get('ssh_password'):
            connect_kwargs['password'] = config['ssh_password']
            print("Using password-based authentication")
        else:
            print("No authentication method provided")
            return False
        
        # Establish connection
        print("Attempting to connect...")
        conn = await asyncssh.connect(**connect_kwargs)
        
        print("✅ SSH connection established successfully!")
        
        # Test command execution
        print("Testing command execution...")
        result = await conn.run('echo "Hello from asyncssh!" && date')
        print(f"Command output: {result.stdout.strip()}")
        print(f"Exit status: {result.exit_status}")
        
        # Close connection
        conn.close()
        print("✅ Connection test completed successfully!")
        return True
        
    except asyncssh.AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        return False
    except asyncssh.SSHException as e:
        print(f"❌ SSH connection failed: {e}")
        return False
    except asyncio.TimeoutError:
        print("❌ Connection timed out")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

async def main():
    if len(sys.argv) != 2:
        print("Usage: python test_asyncssh_connection.py <config.json>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    success = await test_connection(config_file)
    
    if success:
        print("\n🎉 asyncssh connection test PASSED!")
        sys.exit(0)
    else:
        print("\n💥 asyncssh connection test FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 
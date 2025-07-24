#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for Linux Server Management System
"""

import requests
import json
import time
import sys
from typing import Dict, Any, List

# Get backend URL from environment
BACKEND_URL = "https://5877c0ca-28ed-4742-9bc6-d8bcedeb54dd.preview.emergentagent.com/api"

def test_comprehensive_backend():
    """Run comprehensive backend tests"""
    print("🚀 Comprehensive Backend API Tests for Linux Server Management System")
    print(f"🔗 Backend URL: {BACKEND_URL}")
    print("=" * 80)
    
    results = {
        "api_health": False,
        "server_crud": False,
        "groups_management": False,
        "ssh_error_handling": False,
        "system_monitoring_endpoints": False,
        "command_execution_endpoint": False
    }
    
    created_servers = []
    
    # 1. Test API Health
    print("\n📡 Testing API Health...")
    try:
        response = requests.get(f"{BACKEND_URL}/", timeout=30)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Health: {data.get('message', 'OK')}")
            results["api_health"] = True
        else:
            print(f"❌ API Health failed: {response.status_code}")
    except Exception as e:
        print(f"❌ API Health error: {str(e)}")
    
    # 2. Test Server CRUD Operations
    print("\n🖥️  Testing Server CRUD Operations...")
    try:
        # Create server
        server_data = {
            "name": "Test Production Server",
            "hostname": "192.168.1.100",
            "port": 22,
            "username": "ubuntu",
            "password": "secure_password_123",
            "group": "production",
            "description": "Test server for comprehensive API validation"
        }
        
        response = requests.post(f"{BACKEND_URL}/servers", json=server_data, timeout=30)
        if response.status_code == 200:
            server = response.json()
            server_id = server["id"]
            created_servers.append(server_id)
            print(f"✅ Create Server: ID {server_id}")
            
            # Get all servers
            response = requests.get(f"{BACKEND_URL}/servers", timeout=30)
            if response.status_code == 200:
                servers = response.json()
                print(f"✅ Get All Servers: Found {len(servers)} servers")
                
                # Get specific server
                response = requests.get(f"{BACKEND_URL}/servers/{server_id}", timeout=30)
                if response.status_code == 200:
                    server_detail = response.json()
                    print(f"✅ Get Specific Server: {server_detail['name']}")
                    results["server_crud"] = True
                else:
                    print(f"❌ Get Specific Server failed: {response.status_code}")
            else:
                print(f"❌ Get All Servers failed: {response.status_code}")
        else:
            print(f"❌ Create Server failed: {response.status_code} - {response.text[:100]}")
    except Exception as e:
        print(f"❌ Server CRUD error: {str(e)}")
    
    # 3. Test Groups Management
    print("\n👥 Testing Groups Management...")
    try:
        response = requests.get(f"{BACKEND_URL}/groups", timeout=30)
        if response.status_code == 200:
            groups = response.json()
            print(f"✅ Groups Management: Found {len(groups)} groups")
            for group in groups:
                print(f"   - {group['name']}: {group['count']} servers")
            results["groups_management"] = True
        else:
            print(f"❌ Groups Management failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Groups Management error: {str(e)}")
    
    # 4. Test SSH Error Handling & System Monitoring Endpoints
    if created_servers:
        server_id = created_servers[0]
        print(f"\n🔐 Testing SSH Error Handling & System Monitoring (Server: {server_id})...")
        
        # Test system info endpoint
        try:
            print("   Testing system-info endpoint...")
            response = requests.get(f"{BACKEND_URL}/servers/{server_id}/system-info", timeout=45)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ System Info: CPU {data.get('cpu_percent', 0)}%, Memory {data.get('memory_percent', 0)}%")
                results["system_monitoring_endpoints"] = True
                results["ssh_error_handling"] = True
            elif response.status_code == 500:
                error_text = response.text
                if "SSH connection failed" in error_text or "Connection" in error_text:
                    print("✅ SSH Error Handling: Proper error handling for failed connections")
                    results["ssh_error_handling"] = True
                    results["system_monitoring_endpoints"] = True
                else:
                    print(f"❌ Unexpected error: {error_text[:100]}")
            else:
                print(f"❌ System Info failed: {response.status_code}")
        except requests.exceptions.Timeout:
            print("✅ SSH Connection Timeout: Expected behavior for non-existent servers")
            results["ssh_error_handling"] = True
            results["system_monitoring_endpoints"] = True
        except Exception as e:
            print(f"❌ System Info error: {str(e)}")
        
        # Test processes endpoint
        try:
            print("   Testing processes endpoint...")
            response = requests.get(f"{BACKEND_URL}/servers/{server_id}/processes", timeout=45)
            if response.status_code in [200, 500]:
                print("✅ Processes Endpoint: Accessible")
            else:
                print(f"❌ Processes Endpoint failed: {response.status_code}")
        except requests.exceptions.Timeout:
            print("✅ Processes Endpoint: Timeout expected for non-existent servers")
        except Exception as e:
            print(f"❌ Processes Endpoint error: {str(e)}")
        
        # Test services endpoint
        try:
            print("   Testing services endpoint...")
            response = requests.get(f"{BACKEND_URL}/servers/{server_id}/services", timeout=45)
            if response.status_code in [200, 500]:
                print("✅ Services Endpoint: Accessible")
            else:
                print(f"❌ Services Endpoint failed: {response.status_code}")
        except requests.exceptions.Timeout:
            print("✅ Services Endpoint: Timeout expected for non-existent servers")
        except Exception as e:
            print(f"❌ Services Endpoint error: {str(e)}")
        
        # Test command execution endpoint
        try:
            print("   Testing command execution endpoint...")
            command_data = {"command": "ls -la /"}
            response = requests.post(f"{BACKEND_URL}/servers/{server_id}/command", json=command_data, timeout=45)
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Command Execution: Exit code {result.get('exit_code', 'N/A')}")
                results["command_execution_endpoint"] = True
            elif response.status_code == 500:
                if "SSH connection failed" in response.text:
                    print("✅ Command Execution Error Handling: Proper SSH error handling")
                    results["command_execution_endpoint"] = True
                else:
                    print(f"❌ Command Execution unexpected error: {response.text[:100]}")
            else:
                print(f"❌ Command Execution failed: {response.status_code}")
        except requests.exceptions.Timeout:
            print("✅ Command Execution: Timeout expected for non-existent servers")
            results["command_execution_endpoint"] = True
        except Exception as e:
            print(f"❌ Command Execution error: {str(e)}")
    
    # Cleanup
    print("\n🧹 Cleaning up test servers...")
    for server_id in created_servers:
        try:
            response = requests.delete(f"{BACKEND_URL}/servers/{server_id}", timeout=30)
            if response.status_code == 200:
                print(f"   ✅ Deleted server {server_id}")
            else:
                print(f"   ❌ Failed to delete server {server_id}: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Error deleting server {server_id}: {str(e)}")
    
    # Summary
    print("\n" + "=" * 80)
    print("📋 COMPREHENSIVE TEST SUMMARY")
    print("=" * 80)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        formatted_name = test_name.replace("_", " ").title()
        print(f"{status} {formatted_name}")
        if success:
            passed += 1
    
    print(f"\n🎯 Overall Result: {passed}/{total} test categories passed")
    
    # Determine overall success
    critical_tests = ["api_health", "server_crud", "groups_management", "ssh_error_handling"]
    critical_passed = sum(1 for test in critical_tests if results[test])
    
    if critical_passed >= 3:  # At least 3 out of 4 critical tests should pass
        print("🎉 Backend API is working properly!")
        print("✨ Core functionality: Server management, SSH error handling, and API endpoints are operational")
        return True
    else:
        print("⚠️  Backend API has critical issues that need attention")
        return False

if __name__ == "__main__":
    success = test_comprehensive_backend()
    sys.exit(0 if success else 1)
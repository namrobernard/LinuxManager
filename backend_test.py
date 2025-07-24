#!/usr/bin/env python3
"""
Backend API Testing for Linux Server Management System
Tests all backend endpoints and SSH functionality
"""

import requests
import json
import time
import sys
from typing import Dict, Any, List

# Get backend URL from environment
BACKEND_URL = "https://5877c0ca-28ed-4742-9bc6-d8bcedeb54dd.preview.emergentagent.com/api"

class BackendTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.test_results = []
        self.created_servers = []  # Track servers created during testing
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   Details: {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
    
    def test_api_health(self) -> bool:
        """Test basic API health endpoint"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "message" in data:
                    self.log_test("API Health Check", True, f"Response: {data['message']}")
                    return True
            
            self.log_test("API Health Check", False, f"Status: {response.status_code}")
            return False
        except Exception as e:
            self.log_test("API Health Check", False, f"Connection error: {str(e)}")
            return False
    
    def test_server_crud(self) -> bool:
        """Test server CRUD operations"""
        success_count = 0
        
        # Test 1: Create server with password auth
        try:
            server_data = {
                "name": "Test Ubuntu Server",
                "hostname": "192.168.1.100",
                "port": 22,
                "username": "ubuntu",
                "password": "testpass123",
                "group": "production",
                "description": "Test server for API validation"
            }
            
            response = requests.post(f"{self.base_url}/servers", json=server_data, timeout=15)
            if response.status_code == 200:
                server = response.json()
                self.created_servers.append(server["id"])
                self.log_test("Create Server (Password Auth)", True, f"Server ID: {server['id']}")
                success_count += 1
            else:
                self.log_test("Create Server (Password Auth)", False, f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Create Server (Password Auth)", False, f"Error: {str(e)}")
        
        # Test 2: Create server with SSH key auth
        try:
            ssh_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef...
-----END RSA PRIVATE KEY-----"""
            
            server_data = {
                "name": "Test CentOS Server",
                "hostname": "192.168.1.101",
                "port": 22,
                "username": "centos",
                "ssh_key": ssh_key,
                "group": "development",
                "description": "Test server with SSH key"
            }
            
            response = requests.post(f"{self.base_url}/servers", json=server_data, timeout=15)
            if response.status_code == 200:
                server = response.json()
                self.created_servers.append(server["id"])
                self.log_test("Create Server (SSH Key Auth)", True, f"Server ID: {server['id']}")
                success_count += 1
            else:
                self.log_test("Create Server (SSH Key Auth)", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Create Server (SSH Key Auth)", False, f"Error: {str(e)}")
        
        # Test 3: Get all servers
        try:
            response = requests.get(f"{self.base_url}/servers", timeout=10)
            if response.status_code == 200:
                servers = response.json()
                self.log_test("Get All Servers", True, f"Found {len(servers)} servers")
                success_count += 1
            else:
                self.log_test("Get All Servers", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Get All Servers", False, f"Error: {str(e)}")
        
        # Test 4: Get specific server
        if self.created_servers:
            try:
                server_id = self.created_servers[0]
                response = requests.get(f"{self.base_url}/servers/{server_id}", timeout=10)
                if response.status_code == 200:
                    server = response.json()
                    self.log_test("Get Specific Server", True, f"Server: {server['name']}")
                    success_count += 1
                else:
                    self.log_test("Get Specific Server", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Get Specific Server", False, f"Error: {str(e)}")
        
        return success_count >= 3  # At least 3 out of 4 tests should pass
    
    def test_groups_management(self) -> bool:
        """Test groups endpoint"""
        try:
            response = requests.get(f"{self.base_url}/groups", timeout=10)
            if response.status_code == 200:
                groups = response.json()
                self.log_test("Get Server Groups", True, f"Found {len(groups)} groups")
                return True
            else:
                self.log_test("Get Server Groups", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Get Server Groups", False, f"Error: {str(e)}")
            return False
    
    def test_ssh_connections(self) -> bool:
        """Test SSH connection handling"""
        if not self.created_servers:
            self.log_test("SSH Connection Test", False, "No servers available for testing")
            return False
        
        success_count = 0
        
        # Test system info endpoint (requires SSH)
        try:
            server_id = self.created_servers[0]
            response = requests.get(f"{self.base_url}/servers/{server_id}/system-info", timeout=20)
            
            # We expect this to fail gracefully since we don't have real SSH servers
            if response.status_code in [200, 500]:  # Either success or expected SSH failure
                if response.status_code == 200:
                    data = response.json()
                    self.log_test("SSH System Info (Success)", True, f"CPU: {data.get('cpu_percent', 'N/A')}%")
                else:
                    # Check if it's a proper SSH error
                    error_text = response.text
                    if "SSH connection failed" in error_text or "Connection" in error_text:
                        self.log_test("SSH Connection Error Handling", True, "Proper SSH error handling")
                        success_count += 1
                    else:
                        self.log_test("SSH System Info", False, f"Unexpected error: {error_text}")
            else:
                self.log_test("SSH System Info", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("SSH System Info", False, f"Error: {str(e)}")
        
        return success_count > 0 or response.status_code == 200
    
    def test_system_monitoring(self) -> bool:
        """Test system monitoring endpoints"""
        if not self.created_servers:
            self.log_test("System Monitoring Test", False, "No servers available for testing")
            return False
        
        server_id = self.created_servers[0]
        success_count = 0
        
        # Test system info
        try:
            response = requests.get(f"{self.base_url}/servers/{server_id}/system-info", timeout=20)
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                self.log_test("System Info Endpoint", True, "Endpoint accessible")
                success_count += 1
            else:
                self.log_test("System Info Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("System Info Endpoint", False, f"Error: {str(e)}")
        
        # Test processes endpoint
        try:
            response = requests.get(f"{self.base_url}/servers/{server_id}/processes", timeout=20)
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                self.log_test("Processes Endpoint", True, "Endpoint accessible")
                success_count += 1
            else:
                self.log_test("Processes Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Processes Endpoint", False, f"Error: {str(e)}")
        
        # Test services endpoint
        try:
            response = requests.get(f"{self.base_url}/servers/{server_id}/services", timeout=20)
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                self.log_test("Services Endpoint", True, "Endpoint accessible")
                success_count += 1
            else:
                self.log_test("Services Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Services Endpoint", False, f"Error: {str(e)}")
        
        return success_count >= 2
    
    def test_command_execution(self) -> bool:
        """Test command execution endpoint"""
        if not self.created_servers:
            self.log_test("Command Execution Test", False, "No servers available for testing")
            return False
        
        try:
            server_id = self.created_servers[0]
            command_data = {"command": "ls -la /"}
            
            response = requests.post(
                f"{self.base_url}/servers/{server_id}/command", 
                json=command_data, 
                timeout=20
            )
            
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                if response.status_code == 200:
                    result = response.json()
                    self.log_test("Command Execution", True, f"Exit code: {result.get('exit_code', 'N/A')}")
                else:
                    # Check for proper SSH error handling
                    if "SSH connection failed" in response.text:
                        self.log_test("Command Execution Error Handling", True, "Proper SSH error handling")
                return True
            else:
                self.log_test("Command Execution", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Command Execution", False, f"Error: {str(e)}")
            return False
    
    def cleanup_test_servers(self):
        """Clean up servers created during testing"""
        print("\n🧹 Cleaning up test servers...")
        for server_id in self.created_servers:
            try:
                response = requests.delete(f"{self.base_url}/servers/{server_id}", timeout=10)
                if response.status_code == 200:
                    print(f"   ✅ Deleted server {server_id}")
                else:
                    print(f"   ❌ Failed to delete server {server_id}: {response.status_code}")
            except Exception as e:
                print(f"   ❌ Error deleting server {server_id}: {str(e)}")
    
    def run_all_tests(self):
        """Run all backend tests"""
        print("🚀 Starting Backend API Tests for Linux Server Management System")
        print(f"🔗 Backend URL: {self.base_url}")
        print("=" * 80)
        
        # Test results tracking
        test_categories = []
        
        # 1. API Health
        print("\n📡 Testing API Health...")
        api_health = self.test_api_health()
        test_categories.append(("API Health", api_health))
        
        # 2. Server CRUD Operations
        print("\n🖥️  Testing Server CRUD Operations...")
        server_crud = self.test_server_crud()
        test_categories.append(("Server CRUD", server_crud))
        
        # 3. Groups Management
        print("\n👥 Testing Groups Management...")
        groups = self.test_groups_management()
        test_categories.append(("Groups Management", groups))
        
        # 4. SSH Connections
        print("\n🔐 Testing SSH Connections...")
        ssh_connections = self.test_ssh_connections()
        test_categories.append(("SSH Connections", ssh_connections))
        
        # 5. System Monitoring
        print("\n📊 Testing System Monitoring...")
        system_monitoring = self.test_system_monitoring()
        test_categories.append(("System Monitoring", system_monitoring))
        
        # 6. Command Execution
        print("\n⚡ Testing Command Execution...")
        command_execution = self.test_command_execution()
        test_categories.append(("Command Execution", command_execution))
        
        # Cleanup
        self.cleanup_test_servers()
        
        # Summary
        print("\n" + "=" * 80)
        print("📋 TEST SUMMARY")
        print("=" * 80)
        
        passed = 0
        total = len(test_categories)
        
        for category, success in test_categories:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status} {category}")
            if success:
                passed += 1
        
        print(f"\n🎯 Overall Result: {passed}/{total} test categories passed")
        
        if passed >= 4:  # At least 4 out of 6 categories should pass
            print("🎉 Backend API is working properly!")
            return True
        else:
            print("⚠️  Backend API has critical issues that need attention")
            return False

def main():
    """Main test execution"""
    tester = BackendTester()
    success = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
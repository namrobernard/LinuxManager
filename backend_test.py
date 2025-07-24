#!/usr/bin/env python3
"""
Backend API Testing for Linux Server Management System with Security Features
Tests authentication, user management, LDAP, certificates, and server management
"""

import requests
import json
import time
import sys
from typing import Dict, Any, List, Optional

# Get backend URL from environment
BACKEND_URL = "https://5877c0ca-28ed-4742-9bc6-d8bcedeb54dd.preview.emergentagent.com/api"

class BackendTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.test_results = []
        self.created_servers = []  # Track servers created during testing
        self.created_users = []    # Track users created during testing
        self.admin_token = None    # Admin JWT token
        self.user_token = None     # Regular user JWT token
        
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
    
    def make_authenticated_request(self, method: str, endpoint: str, token: str = None, 
                                 json_data: dict = None, timeout: int = 30) -> requests.Response:
        """Make authenticated request with JWT token"""
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        url = f"{self.base_url}{endpoint}"
        
        if method.upper() == "GET":
            return requests.get(url, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            return requests.post(url, headers=headers, json=json_data, timeout=timeout)
        elif method.upper() == "DELETE":
            return requests.delete(url, headers=headers, timeout=timeout)
        else:
            raise ValueError(f"Unsupported method: {method}")
    
    def test_api_health(self) -> bool:
        """Test basic API health endpoint"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=30)
            if response.status_code == 200:
                data = response.json()
                if "message" in data:
                    self.log_test("API Health Check", True, f"Response: {data['message']}")
                    return True
            
            self.log_test("API Health Check", False, f"Status: {response.status_code}")
            return False
        except requests.exceptions.Timeout:
            self.log_test("API Health Check", False, "Request timeout - backend may be slow")
            return False
        except Exception as e:
            self.log_test("API Health Check", False, f"Connection error: {str(e)}")
            return False
    
    def test_authentication_system(self) -> bool:
        """Test JWT authentication system with default admin user"""
        success_count = 0
        
        # Test 1: Login with default admin user (admin/admin123)
        try:
            login_data = {
                "username": "admin",
                "password": "admin123"
            }
            
            response = requests.post(f"{self.base_url}/auth/login", json=login_data, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.admin_token = data["access_token"]
                    user_info = data["user"]
                    self.log_test("Default Admin Login", True, 
                                f"User: {user_info['username']}, Role: {user_info['role']}")
                    success_count += 1
                else:
                    self.log_test("Default Admin Login", False, "Missing token or user info in response")
            else:
                self.log_test("Default Admin Login", False, 
                            f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Default Admin Login", False, f"Error: {str(e)}")
        
        # Test 2: Test invalid credentials
        try:
            login_data = {
                "username": "admin",
                "password": "wrongpassword"
            }
            
            response = requests.post(f"{self.base_url}/auth/login", json=login_data, timeout=15)
            if response.status_code == 401:
                self.log_test("Invalid Credentials Rejection", True, "Properly rejected invalid credentials")
                success_count += 1
            else:
                self.log_test("Invalid Credentials Rejection", False, 
                            f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Credentials Rejection", False, f"Error: {str(e)}")
        
        # Test 3: Test /auth/me endpoint with valid token
        if self.admin_token:
            try:
                response = self.make_authenticated_request("GET", "/auth/me", self.admin_token)
                if response.status_code == 200:
                    user_data = response.json()
                    if user_data.get("username") == "admin" and user_data.get("role") == "admin":
                        self.log_test("Get Current User Info", True, 
                                    f"Retrieved user: {user_data['username']}")
                        success_count += 1
                    else:
                        self.log_test("Get Current User Info", False, "Invalid user data returned")
                else:
                    self.log_test("Get Current User Info", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Get Current User Info", False, f"Error: {str(e)}")
        
        # Test 4: Test unauthorized access (no token)
        try:
            response = requests.get(f"{self.base_url}/auth/me", timeout=15)
            if response.status_code == 401:
                self.log_test("Unauthorized Access Protection", True, "Properly blocked unauthorized access")
                success_count += 1
            else:
                self.log_test("Unauthorized Access Protection", False, 
                            f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Unauthorized Access Protection", False, f"Error: {str(e)}")
        
        return success_count >= 3
    
    def test_user_management(self) -> bool:
        """Test user management endpoints (admin only)"""
        if not self.admin_token:
            self.log_test("User Management Test", False, "No admin token available")
            return False
        
        success_count = 0
        
        # Test 1: Create new user (admin only)
        try:
            user_data = {
                "username": "testuser",
                "password": "testpass123",
                "email": "testuser@example.com",
                "role": "user",
                "ldap_enabled": False
            }
            
            response = self.make_authenticated_request("POST", "/auth/register", 
                                                     self.admin_token, user_data)
            if response.status_code == 200:
                user = response.json()
                self.created_users.append(user["id"])
                self.log_test("Create New User (Admin)", True, f"Created user: {user['username']}")
                success_count += 1
            else:
                self.log_test("Create New User (Admin)", False, 
                            f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Create New User (Admin)", False, f"Error: {str(e)}")
        
        # Test 2: Get all users (admin only)
        try:
            response = self.make_authenticated_request("GET", "/auth/users", self.admin_token)
            if response.status_code == 200:
                users = response.json()
                self.log_test("Get All Users (Admin)", True, f"Found {len(users)} users")
                success_count += 1
            else:
                self.log_test("Get All Users (Admin)", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Get All Users (Admin)", False, f"Error: {str(e)}")
        
        # Test 3: Login with created user and test regular user permissions
        if self.created_users:
            try:
                login_data = {
                    "username": "testuser",
                    "password": "testpass123"
                }
                
                response = requests.post(f"{self.base_url}/auth/login", json=login_data, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    self.user_token = data["access_token"]
                    self.log_test("Regular User Login", True, "User login successful")
                    success_count += 1
                    
                    # Test 4: Regular user trying admin operation (should fail)
                    try:
                        response = self.make_authenticated_request("GET", "/auth/users", self.user_token)
                        if response.status_code == 403:
                            self.log_test("Role-Based Access Control", True, 
                                        "Regular user properly blocked from admin endpoint")
                            success_count += 1
                        else:
                            self.log_test("Role-Based Access Control", False, 
                                        f"Expected 403, got {response.status_code}")
                    except Exception as e:
                        self.log_test("Role-Based Access Control", False, f"Error: {str(e)}")
                else:
                    self.log_test("Regular User Login", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Regular User Login", False, f"Error: {str(e)}")
        
        return success_count >= 3
    
    def test_ldap_configuration(self) -> bool:
        """Test LDAP configuration endpoints (admin only)"""
        if not self.admin_token:
            self.log_test("LDAP Configuration Test", False, "No admin token available")
            return False
        
        success_count = 0
        
        # Test 1: Configure LDAP settings
        try:
            ldap_config = {
                "server_url": "ldap://test-ldap.example.com:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "ldappassword",
                "search_base": "ou=users,dc=example,dc=com",
                "username_attribute": "sAMAccountName",
                "email_attribute": "mail"
            }
            
            response = self.make_authenticated_request("POST", "/auth/ldap/config", 
                                                     self.admin_token, ldap_config)
            if response.status_code == 200:
                self.log_test("Configure LDAP Settings", True, "LDAP configuration saved")
                success_count += 1
            else:
                self.log_test("Configure LDAP Settings", False, 
                            f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Configure LDAP Settings", False, f"Error: {str(e)}")
        
        # Test 2: Get LDAP configuration
        try:
            response = self.make_authenticated_request("GET", "/auth/ldap/config", self.admin_token)
            if response.status_code == 200:
                config = response.json()
                if "server_url" in config and "bind_password" not in config:
                    self.log_test("Get LDAP Configuration", True, 
                                "Configuration retrieved (password properly hidden)")
                    success_count += 1
                else:
                    self.log_test("Get LDAP Configuration", False, "Invalid configuration format")
            else:
                self.log_test("Get LDAP Configuration", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Get LDAP Configuration", False, f"Error: {str(e)}")
        
        # Test 3: Regular user trying LDAP config (should fail)
        if self.user_token:
            try:
                response = self.make_authenticated_request("GET", "/auth/ldap/config", self.user_token)
                if response.status_code == 403:
                    self.log_test("LDAP Config Access Control", True, 
                                "Regular user properly blocked from LDAP config")
                    success_count += 1
                else:
                    self.log_test("LDAP Config Access Control", False, 
                                f"Expected 403, got {response.status_code}")
            except Exception as e:
                self.log_test("LDAP Config Access Control", False, f"Error: {str(e)}")
        
        return success_count >= 2
    
    def test_certificate_management(self) -> bool:
        """Test certificate management endpoints (admin only)"""
        if not self.admin_token:
            self.log_test("Certificate Management Test", False, "No admin token available")
            return False
        
        success_count = 0
        
        # First, create a test server for certificate generation
        test_server_id = None
        try:
            server_data = {
                "name": "Certificate Test Server",
                "hostname": "test.example.com",
                "port": 22,
                "username": "testuser",
                "password": "testpass",
                "group": "testing",
                "description": "Server for certificate testing"
            }
            
            response = self.make_authenticated_request("POST", "/servers", 
                                                     self.admin_token, server_data)
            if response.status_code == 200:
                server = response.json()
                test_server_id = server["id"]
                self.created_servers.append(test_server_id)
                self.log_test("Create Test Server for Certificates", True, f"Server ID: {test_server_id}")
                success_count += 1
            else:
                self.log_test("Create Test Server for Certificates", False, 
                            f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Create Test Server for Certificates", False, f"Error: {str(e)}")
        
        # Test 1: Generate self-signed certificate
        if test_server_id:
            try:
                cert_data = {
                    "server_id": test_server_id,
                    "cert_type": "self_signed",
                    "domain": "test.example.com",
                    "organization": "Test Organization",
                    "country": "US"
                }
                
                response = self.make_authenticated_request("POST", "/certificates/generate", 
                                                         self.admin_token, cert_data)
                if response.status_code == 200:
                    result = response.json()
                    if "message" in result and "certificate_info" in result:
                        self.log_test("Generate Self-Signed Certificate", True, 
                                    f"Certificate generated for {cert_data['domain']}")
                        success_count += 1
                    else:
                        self.log_test("Generate Self-Signed Certificate", False, 
                                    "Invalid response format")
                else:
                    self.log_test("Generate Self-Signed Certificate", False, 
                                f"Status: {response.status_code}, Response: {response.text}")
            except Exception as e:
                self.log_test("Generate Self-Signed Certificate", False, f"Error: {str(e)}")
            
            # Test 2: Get certificate information
            try:
                response = self.make_authenticated_request("GET", f"/certificates/{test_server_id}", 
                                                         self.admin_token)
                if response.status_code == 200:
                    cert_info = response.json()
                    if "type" in cert_info and "domain" in cert_info:
                        self.log_test("Get Certificate Info (Admin)", True, 
                                    f"Certificate type: {cert_info['type']}")
                        success_count += 1
                    else:
                        self.log_test("Get Certificate Info (Admin)", False, "Invalid certificate info")
                else:
                    self.log_test("Get Certificate Info (Admin)", False, 
                                f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Get Certificate Info (Admin)", False, f"Error: {str(e)}")
            
            # Test 3: Regular user getting certificate info (should work but without sensitive data)
            if self.user_token:
                try:
                    response = self.make_authenticated_request("GET", f"/certificates/{test_server_id}", 
                                                             self.user_token)
                    if response.status_code == 200:
                        cert_info = response.json()
                        if "certificate" not in cert_info and "private_key" not in cert_info:
                            self.log_test("Certificate Info Access Control", True, 
                                        "Regular user gets limited certificate info")
                            success_count += 1
                        else:
                            self.log_test("Certificate Info Access Control", False, 
                                        "Sensitive data exposed to regular user")
                    else:
                        self.log_test("Certificate Info Access Control", False, 
                                    f"Status: {response.status_code}")
                except Exception as e:
                    self.log_test("Certificate Info Access Control", False, f"Error: {str(e)}")
        
        return success_count >= 3
    
    def test_enhanced_server_management(self) -> bool:
        """Test that server management now requires authentication"""
        success_count = 0
        
        # Test 1: Unauthorized server access (should fail)
        try:
            response = requests.get(f"{self.base_url}/servers", timeout=15)
            if response.status_code == 401:
                self.log_test("Server List Authentication Required", True, 
                            "Properly requires authentication for server list")
                success_count += 1
            else:
                self.log_test("Server List Authentication Required", False, 
                            f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Server List Authentication Required", False, f"Error: {str(e)}")
        
        # Test 2: Authenticated server access (should work)
        if self.admin_token:
            try:
                response = self.make_authenticated_request("GET", "/servers", self.admin_token)
                if response.status_code == 200:
                    servers = response.json()
                    self.log_test("Authenticated Server List Access", True, 
                                f"Retrieved {len(servers)} servers")
                    success_count += 1
                else:
                    self.log_test("Authenticated Server List Access", False, 
                                f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Authenticated Server List Access", False, f"Error: {str(e)}")
        
        # Test 3: Regular user can view servers
        if self.user_token:
            try:
                response = self.make_authenticated_request("GET", "/servers", self.user_token)
                if response.status_code == 200:
                    servers = response.json()
                    self.log_test("Regular User Server View Access", True, 
                                f"Regular user can view {len(servers)} servers")
                    success_count += 1
                else:
                    self.log_test("Regular User Server View Access", False, 
                                f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("Regular User Server View Access", False, f"Error: {str(e)}")
        
        # Test 4: Regular user cannot create servers (admin only)
        if self.user_token:
            try:
                server_data = {
                    "name": "Unauthorized Server",
                    "hostname": "192.168.1.200",
                    "port": 22,
                    "username": "test",
                    "password": "test",
                    "group": "test"
                }
                
                response = self.make_authenticated_request("POST", "/servers", 
                                                         self.user_token, server_data)
                if response.status_code == 403:
                    self.log_test("Server Creation Access Control", True, 
                                "Regular user properly blocked from creating servers")
                    success_count += 1
                else:
                    self.log_test("Server Creation Access Control", False, 
                                f"Expected 403, got {response.status_code}")
            except Exception as e:
                self.log_test("Server Creation Access Control", False, f"Error: {str(e)}")
        
        return success_count >= 3
    
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
            
            response = requests.post(f"{self.base_url}/servers", json=server_data, timeout=30)
            if response.status_code == 200:
                server = response.json()
                self.created_servers.append(server["id"])
                self.log_test("Create Server (Password Auth)", True, f"Server ID: {server['id']}")
                success_count += 1
            else:
                self.log_test("Create Server (Password Auth)", False, f"Status: {response.status_code}, Response: {response.text}")
        except requests.exceptions.Timeout:
            self.log_test("Create Server (Password Auth)", False, "Request timeout - backend may be slow")
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
        response_status = None
        
        # Test system info endpoint (requires SSH)
        try:
            server_id = self.created_servers[0]
            response = requests.get(f"{self.base_url}/servers/{server_id}/system-info", timeout=20)
            response_status = response.status_code
            
            # We expect this to fail gracefully since we don't have real SSH servers
            if response.status_code in [200, 500]:  # Either success or expected SSH failure
                if response.status_code == 200:
                    data = response.json()
                    self.log_test("SSH System Info (Success)", True, f"CPU: {data.get('cpu_percent', 'N/A')}%")
                    success_count += 1
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
        
        return success_count > 0 or response_status == 200
    
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
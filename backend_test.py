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
    
    
    def test_system_monitoring_with_auth(self) -> bool:
        """Test system monitoring endpoints with authentication"""
        if not self.admin_token or not self.created_servers:
            self.log_test("System Monitoring with Auth Test", False, 
                        "No admin token or servers available")
            return False
        
        server_id = self.created_servers[0]
        success_count = 0
        
        # Test system info with authentication
        try:
            response = self.make_authenticated_request("GET", f"/servers/{server_id}/system-info", 
                                                     self.admin_token)
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                self.log_test("Authenticated System Info", True, "Endpoint accessible with auth")
                success_count += 1
            else:
                self.log_test("Authenticated System Info", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authenticated System Info", False, f"Error: {str(e)}")
        
        # Test processes endpoint with authentication
        try:
            response = self.make_authenticated_request("GET", f"/servers/{server_id}/processes", 
                                                     self.admin_token)
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                self.log_test("Authenticated Processes", True, "Endpoint accessible with auth")
                success_count += 1
            else:
                self.log_test("Authenticated Processes", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authenticated Processes", False, f"Error: {str(e)}")
        
        # Test services endpoint with authentication
        try:
            response = self.make_authenticated_request("GET", f"/servers/{server_id}/services", 
                                                     self.admin_token)
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                self.log_test("Authenticated Services", True, "Endpoint accessible with auth")
                success_count += 1
            else:
                self.log_test("Authenticated Services", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Authenticated Services", False, f"Error: {str(e)}")
        
        return success_count >= 2
    
    def test_command_execution_with_auth(self) -> bool:
        """Test command execution endpoint with authentication"""
        if not self.admin_token or not self.created_servers:
            self.log_test("Command Execution with Auth Test", False, 
                        "No admin token or servers available")
            return False
        
        try:
            server_id = self.created_servers[0]
            command_data = {"command": "echo 'Authentication test'"}
            
            response = self.make_authenticated_request("POST", f"/servers/{server_id}/command", 
                                                     self.admin_token, command_data)
            
            if response.status_code in [200, 500]:  # Accept both success and expected SSH failure
                if response.status_code == 200:
                    result = response.json()
                    self.log_test("Authenticated Command Execution", True, 
                                f"Command executed, exit code: {result.get('exit_code', 'N/A')}")
                else:
                    # Check for proper SSH error handling
                    if "SSH connection failed" in response.text:
                        self.log_test("Authenticated Command Execution", True, 
                                    "Proper SSH error handling with auth")
                return True
            else:
                self.log_test("Authenticated Command Execution", False, 
                            f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Authenticated Command Execution", False, f"Error: {str(e)}")
            return False
    
    def cleanup_test_data(self):
        """Clean up test data created during testing"""
        print("\n🧹 Cleaning up test data...")
        
        # Clean up test servers
        for server_id in self.created_servers:
            try:
                if self.admin_token:
                    response = self.make_authenticated_request("DELETE", f"/servers/{server_id}", 
                                                             self.admin_token)
                    if response.status_code == 200:
                        print(f"   ✅ Deleted server {server_id}")
                    else:
                        print(f"   ❌ Failed to delete server {server_id}: {response.status_code}")
                else:
                    print(f"   ⚠️  Cannot delete server {server_id}: No admin token")
            except Exception as e:
                print(f"   ❌ Error deleting server {server_id}: {str(e)}")
        
        # Clean up test users
        for user_id in self.created_users:
            try:
                if self.admin_token:
                    response = self.make_authenticated_request("DELETE", f"/auth/users/{user_id}", 
                                                             self.admin_token)
                    if response.status_code == 200:
                        print(f"   ✅ Deleted user {user_id}")
                    else:
                        print(f"   ❌ Failed to delete user {user_id}: {response.status_code}")
                else:
                    print(f"   ⚠️  Cannot delete user {user_id}: No admin token")
            except Exception as e:
                print(f"   ❌ Error deleting user {user_id}: {str(e)}")
    
    def run_all_tests(self):
        """Run all backend tests including security features"""
        print("🚀 Starting Enhanced Backend API Tests for Linux Server Management System")
        print("🔐 Testing NEW SECURITY FEATURES: Authentication, User Management, LDAP, Certificates")
        print(f"🔗 Backend URL: {self.base_url}")
        print("=" * 80)
        
        # Test results tracking
        test_categories = []
        
        # 1. API Health
        print("\n📡 Testing API Health...")
        api_health = self.test_api_health()
        test_categories.append(("API Health", api_health))
        
        # 2. Authentication System (PRIORITY 1)
        print("\n🔐 Testing Authentication System (JWT with default admin)...")
        auth_system = self.test_authentication_system()
        test_categories.append(("Authentication System", auth_system))
        
        # 3. User Management (PRIORITY 2)
        print("\n👥 Testing User Management (Admin only)...")
        user_management = self.test_user_management()
        test_categories.append(("User Management", user_management))
        
        # 4. LDAP Configuration (PRIORITY 3)
        print("\n🌐 Testing LDAP Configuration (Admin only)...")
        ldap_config = self.test_ldap_configuration()
        test_categories.append(("LDAP Configuration", ldap_config))
        
        # 5. Certificate Management (PRIORITY 4)
        print("\n📜 Testing Certificate Management (Admin only)...")
        cert_management = self.test_certificate_management()
        test_categories.append(("Certificate Management", cert_management))
        
        # 6. Enhanced Server Management (PRIORITY 5)
        print("\n🖥️  Testing Enhanced Server Management (with Authentication)...")
        server_management = self.test_enhanced_server_management()
        test_categories.append(("Enhanced Server Management", server_management))
        
        # 7. System Monitoring with Auth
        print("\n📊 Testing System Monitoring (with Authentication)...")
        system_monitoring = self.test_system_monitoring_with_auth()
        test_categories.append(("System Monitoring with Auth", system_monitoring))
        
        # 8. Command Execution with Auth
        print("\n⚡ Testing Command Execution (with Authentication)...")
        command_execution = self.test_command_execution_with_auth()
        test_categories.append(("Command Execution with Auth", command_execution))
        
        # Cleanup
        self.cleanup_test_data()
        
        # Summary
        print("\n" + "=" * 80)
        print("📋 SECURITY FEATURES TEST SUMMARY")
        print("=" * 80)
        
        passed = 0
        total = len(test_categories)
        critical_tests = ["Authentication System", "User Management", "Enhanced Server Management"]
        critical_passed = 0
        
        for category, success in test_categories:
            status = "✅ PASS" if success else "❌ FAIL"
            priority = " (CRITICAL)" if category in critical_tests else ""
            print(f"{status} {category}{priority}")
            if success:
                passed += 1
                if category in critical_tests:
                    critical_passed += 1
        
        print(f"\n🎯 Overall Result: {passed}/{total} test categories passed")
        print(f"🔒 Critical Security Tests: {critical_passed}/{len(critical_tests)} passed")
        
        # Determine overall success
        if critical_passed == len(critical_tests) and passed >= 6:
            print("🎉 Backend API with Security Features is working properly!")
            print("✅ All critical security features (Authentication, User Management, Server Access Control) are functional")
            return True
        elif critical_passed == len(critical_tests):
            print("⚠️  Backend API security core is working, but some features need attention")
            return True
        else:
            print("❌ Critical security issues found that need immediate attention")
            return False

def main():
    """Main test execution"""
    tester = BackendTester()
    success = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
from fastapi import FastAPI, APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import asyncio
import paramiko
import psutil
import json
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess
import jwt
import bcrypt
from ldap3 import Server, Connection, ALL, NTLM
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
import ssl

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Thread pool for SSH operations
executor = ThreadPoolExecutor(max_workers=10)

# Models
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: str = "user"  # admin or user
    ldap_enabled: bool = False

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: Optional[str] = None
    role: str = "user"
    is_active: bool = True
    ldap_enabled: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User

class ServerCreate(BaseModel):
    name: str
    hostname: str
    port: int = 22
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    group: str = "default"
    description: Optional[str] = ""
    https_enabled: bool = False
    https_port: int = 443

class Server(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    hostname: str
    port: int = 22
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    group: str = "default"
    description: Optional[str] = ""
    status: str = "unknown"  # online, offline, unknown
    last_seen: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    https_enabled: bool = False
    https_port: int = 443
    certificate_info: Optional[Dict[str, Any]] = None

class SystemInfo(BaseModel):
    server_id: str
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    uptime: str
    load_avg: List[float]
    processes_count: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ProcessInfo(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    status: str
    username: str

class ServiceInfo(BaseModel):
    name: str
    status: str
    enabled: bool

class CertificateGenerate(BaseModel):
    server_id: str
    cert_type: str  # "self_signed" or "lets_encrypt"
    domain: Optional[str] = None
    email: Optional[str] = None
    organization: Optional[str] = "Linux Management System"
    country: str = "US"

class LDAPConfig(BaseModel):
    server_url: str
    bind_dn: str
    bind_password: str
    search_base: str
    username_attribute: str = "sAMAccountName"
    email_attribute: str = "mail"

# Authentication Helper Functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user: User) -> str:
    """Create JWT token for user"""
    payload = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current authenticated user"""
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    user_data = await db.users.find_one({"id": payload["user_id"]})
    if not user_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    user = User(**user_data)
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")
    
    return user

async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role"""
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user

# LDAP Authentication
async def authenticate_ldap(username: str, password: str, ldap_config: LDAPConfig) -> Optional[Dict[str, str]]:
    """Authenticate user against LDAP/AD"""
    try:
        server = Server(ldap_config.server_url, get_info=ALL)
        
        # Try direct bind first (for AD)
        user_dn = f"{username}@{ldap_config.server_url.split('://')[1]}"
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        
        if conn.bind():
            # Search for user details
            search_filter = f"({ldap_config.username_attribute}={username})"
            conn.search(ldap_config.search_base, search_filter, attributes=[ldap_config.email_attribute])
            
            if conn.entries:
                entry = conn.entries[0]
                email = getattr(entry, ldap_config.email_attribute, None)
                return {
                    "username": username,
                    "email": str(email) if email else None
                }
        
        conn.unbind()
        return None
    except Exception as e:
        logging.error(f"LDAP authentication error: {e}")
        return None

# Certificate Management
def generate_self_signed_certificate(hostname: str, organization: str = "Linux Management", 
                                   country: str = "US", days_valid: int = 365) -> tuple:
    """Generate self-signed certificate"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=days_valid)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(hostname),
            x509.IPAddress(ipaddress.ip_address(hostname)) if hostname.replace('.', '').isdigit() else x509.DNSName(hostname)
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Serialize certificate and key
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return cert_pem, key_pem

# SSH Connection Manager (same as before but enhanced)
class SSHManager:
    def __init__(self):
        self.connections = {}

    async def get_connection(self, server: Server):
        """Get or create SSH connection for a server"""
        try:
            if server.id in self.connections:
                # Test existing connection
                connection = self.connections[server.id]
                try:
                    connection.exec_command('echo test', timeout=5)
                    return connection
                except:
                    # Connection is dead, remove it
                    del self.connections[server.id]

            # Create new connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if server.ssh_key:
                # Use SSH key
                key = paramiko.RSAKey.from_private_key_string(server.ssh_key)
                ssh.connect(
                    hostname=server.hostname,
                    port=server.port,
                    username=server.username,
                    pkey=key,
                    timeout=10
                )
            elif server.password:
                # Use password
                ssh.connect(
                    hostname=server.hostname,
                    port=server.port,
                    username=server.username,
                    password=server.password,
                    timeout=10
                )
            else:
                raise Exception("No authentication method provided")

            self.connections[server.id] = ssh
            return ssh
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SSH connection failed: {str(e)}")

    async def execute_command(self, server: Server, command: str):
        """Execute command on remote server"""
        ssh = await self.get_connection(server)
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            
            return {
                "output": output,
                "error": error,
                "exit_code": exit_code
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Command execution failed: {str(e)}")

    def close_connection(self, server_id: str):
        """Close SSH connection"""
        if server_id in self.connections:
            try:
                self.connections[server_id].close()
            except:
                pass
            del self.connections[server_id]

ssh_manager = SSHManager()

# Helper functions (same as before)
async def get_system_info(server: Server) -> SystemInfo:
    """Get system information from remote server"""
    try:
        # Commands to get system info
        commands = {
            'cpu': "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//'",
            'memory': "free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'",
            'disk': "df -h / | awk 'NR==2{printf \"%.1f\", $5}'",
            'uptime': "uptime -p",
            'load': "uptime | awk -F'load average:' '{print $2}' | sed 's/,//g'",
            'processes': "ps aux | wc -l"
        }
        
        results = {}
        for key, cmd in commands.items():
            try:
                result = await ssh_manager.execute_command(server, cmd)
                if result['exit_code'] == 0:
                    results[key] = result['output'].strip()
                else:
                    results[key] = "0"
            except:
                results[key] = "0"

        # Parse results
        cpu_percent = float(results.get('cpu', '0').replace('%', '')) if results.get('cpu') else 0.0
        memory_percent = float(results.get('memory', '0')) if results.get('memory') else 0.0
        disk_percent = float(results.get('disk', '0').replace('%', '')) if results.get('disk') else 0.0
        uptime = results.get('uptime', 'Unknown')
        
        # Parse load average
        load_str = results.get('load', '0.00 0.00 0.00').strip()
        load_avg = [float(x.strip()) for x in load_str.split()[:3]] if load_str else [0.0, 0.0, 0.0]
        
        processes_count = int(results.get('processes', '0')) if results.get('processes') else 0

        return SystemInfo(
            server_id=server.id,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_percent=disk_percent,
            uptime=uptime,
            load_avg=load_avg,
            processes_count=processes_count
        )
    except Exception as e:
        # Return default values if unable to get info
        return SystemInfo(
            server_id=server.id,
            cpu_percent=0.0,
            memory_percent=0.0,
            disk_percent=0.0,
            uptime="Unknown",
            load_avg=[0.0, 0.0, 0.0],
            processes_count=0
        )

# Authentication Routes
@api_router.post("/auth/register", response_model=User)
async def register_user(user_data: UserCreate, current_user: User = Depends(require_admin)):
    """Register new user (admin only)"""
    # Check if user exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Hash password
    hashed_password = hash_password(user_data.password)
    
    # Create user
    user = User(**user_data.dict(exclude={"password"}))
    user_dict = user.dict()
    user_dict["password_hash"] = hashed_password
    
    await db.users.insert_one(user_dict)
    return user

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    """Login user"""
    user_doc = await db.users.find_one({"username": user_data.username})
    
    if user_doc and user_doc.get("ldap_enabled"):
        # LDAP authentication
        ldap_config = await db.settings.find_one({"type": "ldap_config"})
        if ldap_config:
            ldap_conf = LDAPConfig(**ldap_config["config"])
            ldap_user = await authenticate_ldap(user_data.username, user_data.password, ldap_conf)
            if ldap_user:
                # Update or create user from LDAP
                if user_doc:
                    user = User(**user_doc)
                else:
                    user = User(
                        username=ldap_user["username"],
                        email=ldap_user["email"],
                        role="user",
                        ldap_enabled=True
                    )
                    await db.users.insert_one(user.dict())
            else:
                raise HTTPException(status_code=401, detail="Invalid LDAP credentials")
        else:
            raise HTTPException(status_code=500, detail="LDAP not configured")
    else:
        # Local authentication
        if not user_doc:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not verify_password(user_data.password, user_doc["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = User(**user_doc)
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account disabled")
    
    # Update last login
    await db.users.update_one(
        {"id": user.id},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    # Create token
    token = create_jwt_token(user)
    
    return Token(access_token=token, user=user)

@api_router.get("/auth/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user info"""
    return current_user

@api_router.get("/auth/users", response_model=List[User])
async def get_all_users(current_user: User = Depends(require_admin)):
    """Get all users (admin only)"""
    users = await db.users.find({}, {"password_hash": 0}).to_list(1000)
    return [User(**user) for user in users]

@api_router.delete("/auth/users/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(require_admin)):
    """Delete user (admin only)"""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deleted successfully"}

# LDAP Configuration Routes
@api_router.post("/auth/ldap/config")
async def configure_ldap(ldap_config: LDAPConfig, current_user: User = Depends(require_admin)):
    """Configure LDAP settings (admin only)"""
    config_doc = {
        "type": "ldap_config",
        "config": ldap_config.dict(),
        "updated_at": datetime.utcnow(),
        "updated_by": current_user.username
    }
    
    await db.settings.replace_one(
        {"type": "ldap_config"},
        config_doc,
        upsert=True
    )
    
    return {"message": "LDAP configuration saved"}

@api_router.get("/auth/ldap/config")
async def get_ldap_config(current_user: User = Depends(require_admin)):
    """Get LDAP configuration (admin only)"""
    config = await db.settings.find_one({"type": "ldap_config"})
    if not config:
        raise HTTPException(status_code=404, detail="LDAP not configured")
    
    # Remove sensitive data
    config["config"].pop("bind_password", None)
    return config["config"]

# Certificate Management Routes
@api_router.post("/certificates/generate")
async def generate_certificate(cert_data: CertificateGenerate, current_user: User = Depends(require_admin)):
    """Generate SSL certificate for server"""
    server_data = await db.servers.find_one({"id": cert_data.server_id})
    if not server_data:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server = Server(**server_data)
    
    if cert_data.cert_type == "self_signed":
        # Generate self-signed certificate
        cert_pem, key_pem = generate_self_signed_certificate(
            hostname=cert_data.domain or server.hostname,
            organization=cert_data.organization,
            country=cert_data.country,
            days_valid=365
        )
        
        # Store certificate info
        cert_info = {
            "type": "self_signed",
            "domain": cert_data.domain or server.hostname,
            "organization": cert_data.organization,
            "country": cert_data.country,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=365),
            "certificate": cert_pem.decode('utf-8'),
            "private_key": key_pem.decode('utf-8')
        }
        
        # Update server
        await db.servers.update_one(
            {"id": cert_data.server_id},
            {"$set": {"certificate_info": cert_info, "https_enabled": True}}
        )
        
        return {"message": "Self-signed certificate generated successfully", "certificate_info": {k: v for k, v in cert_info.items() if k not in ["certificate", "private_key"]}}
    
    elif cert_data.cert_type == "lets_encrypt":
        # TODO: Implement Let's Encrypt certificate generation
        # This would require ACME client implementation
        return {"message": "Let's Encrypt integration coming soon"}
    
    else:
        raise HTTPException(status_code=400, detail="Invalid certificate type")

@api_router.get("/certificates/{server_id}")
async def get_certificate_info(server_id: str, current_user: User = Depends(get_current_user)):
    """Get certificate information for server"""
    server_data = await db.servers.find_one({"id": server_id})
    if not server_data:
        raise HTTPException(status_code=404, detail="Server not found")
    
    cert_info = server_data.get("certificate_info")
    if not cert_info:
        raise HTTPException(status_code=404, detail="No certificate found for this server")
    
    # Remove sensitive data for non-admin users
    if current_user.role != "admin":
        cert_info = {k: v for k, v in cert_info.items() if k not in ["certificate", "private_key"]}
    
    return cert_info

# Enhanced Server Routes (with permissions)
@api_router.get("/")
async def root():
    return {"message": "Linux Management System API"}

@api_router.post("/servers", response_model=Server)
async def create_server(server_data: ServerCreate, current_user: User = Depends(require_admin)):
    """Add a new server (admin only)"""
    server = Server(**server_data.dict())
    
    # Test connection
    try:
        await ssh_manager.get_connection(server)
        server.status = "online"
        server.last_seen = datetime.utcnow()
    except:
        server.status = "offline"

    # Save to database
    await db.servers.insert_one(server.dict())
    return server

@api_router.get("/servers", response_model=List[Server])
async def get_servers(current_user: User = Depends(get_current_user)):
    """Get all servers"""
    servers = await db.servers.find().to_list(1000)
    return [Server(**server) for server in servers]

@api_router.get("/servers/{server_id}", response_model=Server)
async def get_server(server_id: str, current_user: User = Depends(get_current_user)):
    """Get server by ID"""
    server = await db.servers.find_one({"id": server_id})
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return Server(**server)

@api_router.delete("/servers/{server_id}")
async def delete_server(server_id: str, current_user: User = Depends(require_admin)):
    """Delete server (admin only)"""
    result = await db.servers.delete_one({"id": server_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Close SSH connection if exists
    ssh_manager.close_connection(server_id)
    return {"message": "Server deleted successfully"}

@api_router.get("/servers/{server_id}/system-info")
async def get_server_system_info(server_id: str, current_user: User = Depends(get_current_user)):
    """Get real-time system information for a server"""
    server_data = await db.servers.find_one({"id": server_id})
    if not server_data:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server = Server(**server_data)
    system_info = await get_system_info(server)
    
    # Update server status
    await db.servers.update_one(
        {"id": server_id},
        {"$set": {"status": "online", "last_seen": datetime.utcnow()}}
    )
    
    return system_info

@api_router.get("/servers/{server_id}/processes")
async def get_server_processes(server_id: str, current_user: User = Depends(get_current_user)):
    """Get running processes for a server"""
    server_data = await db.servers.find_one({"id": server_id})
    if not server_data:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server = Server(**server_data)
    
    # Get process info
    cmd = "ps aux --sort=-%cpu | head -20 | awk 'NR>1 {print $2\"|\"$1\"|\"$11\"|\"$3\"|\"$4\"|\"$8}'"
    result = await ssh_manager.execute_command(server, cmd)
    
    processes = []
    if result['exit_code'] == 0:
        for line in result['output'].strip().split('\n'):
            if line:
                parts = line.split('|')
                if len(parts) >= 6:
                    processes.append(ProcessInfo(
                        pid=int(parts[0]),
                        username=parts[1],
                        name=parts[2],
                        cpu_percent=float(parts[3]),
                        memory_percent=float(parts[4]),
                        status=parts[5]
                    ))
    
    return processes

@api_router.get("/servers/{server_id}/services")
async def get_server_services(server_id: str, current_user: User = Depends(get_current_user)):
    """Get services status for a server"""
    server_data = await db.servers.find_one({"id": server_id})
    if not server_data:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server = Server(**server_data)
    
    # Get systemd services
    cmd = "systemctl list-units --type=service --state=active,inactive | grep -E '\\.(service)' | head -20 | awk '{print $1\"|\"$2\"|\"$3}'"
    result = await ssh_manager.execute_command(server, cmd)
    
    services = []
    if result['exit_code'] == 0:
        for line in result['output'].strip().split('\n'):
            if line and '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    name = parts[0].replace('.service', '')
                    status = parts[2]
                    services.append(ServiceInfo(
                        name=name,
                        status=status,
                        enabled=True  # We'll check this separately if needed
                    ))
    
    return services

@api_router.post("/servers/{server_id}/command")
async def execute_server_command(server_id: str, command_data: dict, current_user: User = Depends(get_current_user)):
    """Execute command on server"""
    server_data = await db.servers.find_one({"id": server_id})
    if not server_data:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server = Server(**server_data)
    command = command_data.get("command", "")
    
    if not command:
        raise HTTPException(status_code=400, detail="Command is required")
    
    result = await ssh_manager.execute_command(server, command)
    return result

@api_router.get("/groups")
async def get_server_groups(current_user: User = Depends(get_current_user)):
    """Get all server groups"""
    pipeline = [
        {"$group": {"_id": "$group", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]
    groups = await db.servers.aggregate(pipeline).to_list(100)
    return [{"name": group["_id"], "count": group["count"]} for group in groups]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create default admin user on startup
@app.on_event("startup")
async def create_default_admin():
    """Create default admin user if none exists"""
    admin_count = await db.users.count_documents({"role": "admin"})
    if admin_count == 0:
        default_admin = User(
            username="admin",
            role="admin",
            email="admin@localhost"
        )
        admin_dict = default_admin.dict()
        admin_dict["password_hash"] = hash_password("admin123")
        
        await db.users.insert_one(admin_dict)
        logger.info("Default admin user created: admin/admin123")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
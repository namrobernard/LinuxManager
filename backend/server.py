from fastapi import FastAPI, APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import asyncio
import paramiko
import psutil
import json
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Thread pool for SSH operations
executor = ThreadPoolExecutor(max_workers=10)

# Models
class ServerCreate(BaseModel):
    name: str
    hostname: str
    port: int = 22
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    group: str = "default"
    description: Optional[str] = ""

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

# SSH Connection Manager
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

# Helper functions
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

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Linux Management System API"}

@api_router.post("/servers", response_model=Server)
async def create_server(server_data: ServerCreate):
    """Add a new server"""
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
async def get_servers():
    """Get all servers"""
    servers = await db.servers.find().to_list(1000)
    return [Server(**server) for server in servers]

@api_router.get("/servers/{server_id}", response_model=Server)
async def get_server(server_id: str):
    """Get server by ID"""
    server = await db.servers.find_one({"id": server_id})
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return Server(**server)

@api_router.delete("/servers/{server_id}")
async def delete_server(server_id: str):
    """Delete server"""
    result = await db.servers.delete_one({"id": server_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Server not found")
    
    # Close SSH connection if exists
    ssh_manager.close_connection(server_id)
    return {"message": "Server deleted successfully"}

@api_router.get("/servers/{server_id}/system-info")
async def get_server_system_info(server_id: str):
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
async def get_server_processes(server_id: str):
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
async def get_server_services(server_id: str):
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
async def execute_server_command(server_id: str, command_data: dict):
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
async def get_server_groups():
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

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
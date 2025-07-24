import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const App = () => {
  const [servers, setServers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState('all');
  const [showAddServer, setShowAddServer] = useState(false);
  const [selectedServer, setSelectedServer] = useState(null);
  const [systemInfo, setSystemInfo] = useState({});
  const [loading, setLoading] = useState(true);

  // New server form state
  const [newServer, setNewServer] = useState({
    name: '',
    hostname: '',
    port: 22,
    username: '',
    password: '',
    ssh_key: '',
    group: 'default',
    description: ''
  });

  useEffect(() => {
    fetchServers();
    fetchGroups();
    
    // Auto-refresh system info every 30 seconds
    const interval = setInterval(() => {
      if (selectedServer) {
        fetchSystemInfo(selectedServer.id);
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [selectedServer]);

  const fetchServers = async () => {
    try {
      const response = await axios.get(`${API}/servers`);
      setServers(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching servers:', error);
      setLoading(false);
    }
  };

  const fetchGroups = async () => {
    try {
      const response = await axios.get(`${API}/groups`);
      setGroups(response.data);
    } catch (error) {
      console.error('Error fetching groups:', error);
    }
  };

  const fetchSystemInfo = async (serverId) => {
    try {
      const response = await axios.get(`${API}/servers/${serverId}/system-info`);
      setSystemInfo(prev => ({
        ...prev,
        [serverId]: response.data
      }));
    } catch (error) {
      console.error('Error fetching system info:', error);
    }
  };

  const addServer = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API}/servers`, newServer);
      setServers([...servers, response.data]);
      setNewServer({
        name: '',
        hostname: '',
        port: 22,
        username: '',
        password: '',
        ssh_key: '',
        group: 'default',
        description: ''
      });
      setShowAddServer(false);
      fetchGroups();
    } catch (error) {
      console.error('Error adding server:', error);
      alert('Erreur lors de l\'ajout du serveur: ' + (error.response?.data?.detail || error.message));
    }
  };

  const deleteServer = async (serverId) => {
    if (window.confirm('Êtes-vous sûr de vouloir supprimer ce serveur ?')) {
      try {
        await axios.delete(`${API}/servers/${serverId}`);
        setServers(servers.filter(s => s.id !== serverId));
        if (selectedServer?.id === serverId) {
          setSelectedServer(null);
        }
        fetchGroups();
      } catch (error) {
        console.error('Error deleting server:', error);
      }
    }
  };

  const selectServer = (server) => {
    setSelectedServer(server);
    fetchSystemInfo(server.id);
  };

  const filteredServers = selectedGroup === 'all' 
    ? servers 
    : servers.filter(s => s.group === selectedGroup);

  const getStatusColor = (status) => {
    switch (status) {
      case 'online': return 'text-green-500';
      case 'offline': return 'text-red-500';
      default: return 'text-yellow-500';
    }
  };

  const getUsageColor = (percentage) => {
    if (percentage > 80) return 'bg-red-500';
    if (percentage > 60) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-xl">Chargement...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-blue-400">
            🐧 Gestionnaire Linux Multi-Serveurs
          </h1>
          <button
            onClick={() => setShowAddServer(true)}
            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition-colors"
          >
            + Ajouter Serveur
          </button>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar - Server List */}
        <div className="w-80 bg-gray-800 border-r border-gray-700 h-screen overflow-y-auto">
          {/* Group Filter */}
          <div className="p-4 border-b border-gray-700">
            <select
              value={selectedGroup}
              onChange={(e) => setSelectedGroup(e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
            >
              <option value="all">Tous les groupes ({servers.length})</option>
              {groups.map(group => (
                <option key={group.name} value={group.name}>
                  {group.name} ({group.count})
                </option>
              ))}
            </select>
          </div>

          {/* Server List */}
          <div className="p-4 space-y-2">
            {filteredServers.map(server => (
              <div
                key={server.id}
                onClick={() => selectServer(server)}
                className={`p-3 rounded-lg cursor-pointer transition-all ${
                  selectedServer?.id === server.id
                    ? 'bg-blue-600 border-blue-500'
                    : 'bg-gray-700 hover:bg-gray-600'
                } border`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold">{server.name}</h3>
                    <p className="text-sm text-gray-300">{server.hostname}</p>
                    <span className="text-xs bg-gray-600 px-2 py-1 rounded mt-1 inline-block">
                      {server.group}
                    </span>
                  </div>
                  <div className="text-right">
                    <div className={`text-sm font-medium ${getStatusColor(server.status)}`}>
                      ● {server.status}
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteServer(server.id);
                      }}
                      className="text-red-400 hover:text-red-300 text-xs mt-1"
                    >
                      Supprimer
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6">
          {selectedServer ? (
            <div>
              {/* Server Header */}
              <div className="bg-gray-800 rounded-lg p-6 mb-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-3xl font-bold text-blue-400">{selectedServer.name}</h2>
                    <p className="text-gray-300">{selectedServer.hostname}:{selectedServer.port}</p>
                    <p className="text-sm text-gray-400 mt-1">{selectedServer.description}</p>
                  </div>
                  <div className={`text-2xl font-bold ${getStatusColor(selectedServer.status)}`}>
                    ● {selectedServer.status.toUpperCase()}
                  </div>
                </div>
              </div>

              {/* System Metrics */}
              {systemInfo[selectedServer.id] && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
                  {/* CPU */}
                  <div className="bg-gray-800 rounded-lg p-4">
                    <h3 className="text-lg font-semibold mb-2">CPU</h3>
                    <div className="text-3xl font-bold text-blue-400 mb-2">
                      {systemInfo[selectedServer.id].cpu_percent.toFixed(1)}%
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getUsageColor(systemInfo[selectedServer.id].cpu_percent)}`}
                        style={{ width: `${Math.min(systemInfo[selectedServer.id].cpu_percent, 100)}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Memory */}
                  <div className="bg-gray-800 rounded-lg p-4">
                    <h3 className="text-lg font-semibold mb-2">Mémoire</h3>
                    <div className="text-3xl font-bold text-green-400 mb-2">
                      {systemInfo[selectedServer.id].memory_percent.toFixed(1)}%
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getUsageColor(systemInfo[selectedServer.id].memory_percent)}`}
                        style={{ width: `${Math.min(systemInfo[selectedServer.id].memory_percent, 100)}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Disk */}
                  <div className="bg-gray-800 rounded-lg p-4">
                    <h3 className="text-lg font-semibold mb-2">Disque</h3>
                    <div className="text-3xl font-bold text-purple-400 mb-2">
                      {systemInfo[selectedServer.id].disk_percent.toFixed(1)}%
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getUsageColor(systemInfo[selectedServer.id].disk_percent)}`}
                        style={{ width: `${Math.min(systemInfo[selectedServer.id].disk_percent, 100)}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Uptime */}
                  <div className="bg-gray-800 rounded-lg p-4">
                    <h3 className="text-lg font-semibold mb-2">Uptime</h3>
                    <div className="text-lg font-bold text-yellow-400 mb-2">
                      {systemInfo[selectedServer.id].uptime}
                    </div>
                    <div className="text-sm text-gray-400">
                      Processus: {systemInfo[selectedServer.id].processes_count}
                    </div>
                  </div>
                </div>
              )}

              {/* Load Average */}
              {systemInfo[selectedServer.id] && (
                <div className="bg-gray-800 rounded-lg p-6 mb-6">
                  <h3 className="text-xl font-semibold mb-4">Charge Système</h3>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-400">
                        {systemInfo[selectedServer.id].load_avg[0]?.toFixed(2) || '0.00'}
                      </div>
                      <div className="text-sm text-gray-400">1 min</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-400">
                        {systemInfo[selectedServer.id].load_avg[1]?.toFixed(2) || '0.00'}
                      </div>
                      <div className="text-sm text-gray-400">5 min</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-purple-400">
                        {systemInfo[selectedServer.id].load_avg[2]?.toFixed(2) || '0.00'}
                      </div>
                      <div className="text-sm text-gray-400">15 min</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Quick Actions */}
              <div className="bg-gray-800 rounded-lg p-6">
                <h3 className="text-xl font-semibold mb-4">Actions Rapides</h3>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <button className="bg-blue-600 hover:bg-blue-700 p-3 rounded-lg transition-colors">
                    📊 Processus
                  </button>
                  <button className="bg-green-600 hover:bg-green-700 p-3 rounded-lg transition-colors">
                    🔧 Services
                  </button>
                  <button className="bg-purple-600 hover:bg-purple-700 p-3 rounded-lg transition-colors">
                    📁 Fichiers
                  </button>
                  <button className="bg-yellow-600 hover:bg-yellow-700 p-3 rounded-lg transition-colors">
                    💻 Terminal
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-96">
              <div className="text-center">
                <div className="text-6xl mb-4">🖥️</div>
                <h2 className="text-2xl font-bold text-gray-400 mb-2">
                  Sélectionnez un serveur
                </h2>
                <p className="text-gray-500">
                  Choisissez un serveur dans la liste pour voir ses informations
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Add Server Modal */}
      {showAddServer && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h3 className="text-xl font-bold mb-4">Ajouter un Serveur</h3>
            <form onSubmit={addServer} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Nom</label>
                <input
                  type="text"
                  value={newServer.name}
                  onChange={(e) => setNewServer({...newServer, name: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Hostname/IP</label>
                <input
                  type="text"
                  value={newServer.hostname}
                  onChange={(e) => setNewServer({...newServer, hostname: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Port SSH</label>
                <input
                  type="number"
                  value={newServer.port}
                  onChange={(e) => setNewServer({...newServer, port: parseInt(e.target.value)})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Nom d'utilisateur</label>
                <input
                  type="text"
                  value={newServer.username}
                  onChange={(e) => setNewServer({...newServer, username: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Mot de passe</label>
                <input
                  type="password"
                  value={newServer.password}
                  onChange={(e) => setNewServer({...newServer, password: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Groupe</label>
                <input
                  type="text"
                  value={newServer.group}
                  onChange={(e) => setNewServer({...newServer, group: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  placeholder="web, database, storage..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  value={newServer.description}
                  onChange={(e) => setNewServer({...newServer, description: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  rows={3}
                />
              </div>
              <div className="flex gap-2 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 py-2 rounded-lg transition-colors"
                >
                  Ajouter
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddServer(false)}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 rounded-lg transition-colors"
                >
                  Annuler
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
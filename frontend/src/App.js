import React, { useState, useEffect, createContext, useContext } from 'react';
import axios from 'axios';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      checkAuth();
    } else {
      setLoading(false);
    }
  }, [token]);

  const checkAuth = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setUser(response.data);
    } catch (error) {
      logout();
    }
    setLoading(false);
  };

  const login = async (username, password) => {
    try {
      const response = await axios.post(`${API}/auth/login`, {
        username,
        password
      });
      
      const { access_token, user: userData } = response.data;
      setToken(access_token);
      setUser(userData);
      localStorage.setItem('token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Erreur de connexion' 
      };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
  };

  const value = {
    user,
    token,
    login,
    logout,
    loading,
    isAdmin: user?.role === 'admin'
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

// Login Component
const Login = () => {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const result = await login(credentials.username, credentials.password);
    
    if (!result.success) {
      setError(result.error);
    }
    
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-96">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-blue-400 mb-2">
            🐧 Linux Manager
          </h1>
          <p className="text-gray-400">Connexion requise</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Nom d'utilisateur
            </label>
            <input
              type="text"
              value={credentials.username}
              onChange={(e) => setCredentials({...credentials, username: e.target.value})}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Mot de passe
            </label>
            <input
              type="password"
              value={credentials.password}
              onChange={(e) => setCredentials({...credentials, password: e.target.value})}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>

          {error && (
            <div className="bg-red-600 bg-opacity-20 border border-red-600 text-red-400 px-4 py-2 rounded">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 py-2 rounded-lg transition-colors"
          >
            {loading ? 'Connexion...' : 'Se connecter'}
          </button>
        </form>

        <div className="mt-6 text-center text-sm text-gray-400">
          <p>Compte par défaut: admin / admin123</p>
        </div>
      </div>
    </div>
  );
};

// User Management Component
const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [showAddUser, setShowAddUser] = useState(false);
  const [showLdapConfig, setShowLdapConfig] = useState(false);
  const [ldapConfig, setLdapConfig] = useState({
    server_url: 'ldap://domain.local:389',
    bind_dn: 'CN=ldap-user,CN=Users,DC=domain,DC=local',
    bind_password: '',
    search_base: 'CN=Users,DC=domain,DC=local',
    username_attribute: 'sAMAccountName',
    email_attribute: 'mail'
  });
  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    email: '',
    role: 'user',
    ldap_enabled: false
  });

  useEffect(() => {
    fetchUsers();
    fetchLdapConfig();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await axios.get(`${API}/auth/users`);
      setUsers(response.data);
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  };

  const fetchLdapConfig = async () => {
    try {
      const response = await axios.get(`${API}/auth/ldap/config`);
      setLdapConfig(response.data);
    } catch (error) {
      // LDAP not configured yet
    }
  };

  const addUser = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/auth/register`, newUser);
      setNewUser({
        username: '',
        password: '',
        email: '',
        role: 'user',
        ldap_enabled: false
      });
      setShowAddUser(false);
      fetchUsers();
    } catch (error) {
      alert('Erreur lors de l\'ajout: ' + (error.response?.data?.detail || error.message));
    }
  };

  const deleteUser = async (userId) => {
    if (window.confirm('Supprimer cet utilisateur ?')) {
      try {
        await axios.delete(`${API}/auth/users/${userId}`);
        fetchUsers();
      } catch (error) {
        alert('Erreur lors de la suppression');
      }
    }
  };

  const saveLdapConfig = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/auth/ldap/config`, ldapConfig);
      setShowLdapConfig(false);
      alert('Configuration LDAP sauvegardée');
    } catch (error) {
      alert('Erreur lors de la sauvegarde LDAP');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">Gestion des Utilisateurs</h2>
        <div className="space-x-2">
          <button
            onClick={() => setShowAddUser(true)}
            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition-colors"
          >
            + Nouvel Utilisateur
          </button>
          <button
            onClick={() => setShowLdapConfig(true)}
            className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg transition-colors"
          >
            ⚙️ Config LDAP
          </button>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-700">
            <tr>
              <th className="px-4 py-3 text-left">Utilisateur</th>
              <th className="px-4 py-3 text-left">Email</th>
              <th className="px-4 py-3 text-left">Rôle</th>
              <th className="px-4 py-3 text-left">Type</th>
              <th className="px-4 py-3 text-left">Dernière connexion</th>
              <th className="px-4 py-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className="border-t border-gray-700">
                <td className="px-4 py-3">{user.username}</td>
                <td className="px-4 py-3">{user.email || '-'}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs ${
                    user.role === 'admin' ? 'bg-red-600' : 'bg-blue-600'
                  }`}>
                    {user.role}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {user.ldap_enabled ? (
                    <span className="text-purple-400">LDAP</span>
                  ) : (
                    <span className="text-green-400">Local</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Jamais'}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => deleteUser(user.id)}
                    className="text-red-400 hover:text-red-300"
                  >
                    Supprimer
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add User Modal */}
      {showAddUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-96">
            <h3 className="text-xl font-bold mb-4">Ajouter un Utilisateur</h3>
            <form onSubmit={addUser} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Nom d'utilisateur</label>
                <input
                  type="text"
                  value={newUser.username}
                  onChange={(e) => setNewUser({...newUser, username: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Mot de passe</label>
                <input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  required={!newUser.ldap_enabled}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Email</label>
                <input
                  type="email"
                  value={newUser.email}
                  onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Rôle</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({...newUser, role: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                >
                  <option value="user">Utilisateur</option>
                  <option value="admin">Administrateur</option>
                </select>
              </div>
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={newUser.ldap_enabled}
                    onChange={(e) => setNewUser({...newUser, ldap_enabled: e.target.checked})}
                    className="mr-2"
                  />
                  Utilisateur LDAP/AD
                </label>
              </div>
              <div className="flex gap-2 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700 py-2 rounded-lg"
                >
                  Ajouter
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddUser(false)}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 rounded-lg"
                >
                  Annuler
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* LDAP Config Modal */}
      {showLdapConfig && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h3 className="text-xl font-bold mb-4">Configuration LDAP/Active Directory</h3>
            <form onSubmit={saveLdapConfig} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">URL du serveur</label>
                <input
                  type="text"
                  value={ldapConfig.server_url}
                  onChange={(e) => setLdapConfig({...ldapConfig, server_url: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  placeholder="ldap://domain.local:389"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">DN de liaison</label>
                <input
                  type="text"
                  value={ldapConfig.bind_dn}
                  onChange={(e) => setLdapConfig({...ldapConfig, bind_dn: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  placeholder="CN=ldap-user,CN=Users,DC=domain,DC=local"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Mot de passe de liaison</label>
                <input
                  type="password"
                  value={ldapConfig.bind_password}
                  onChange={(e) => setLdapConfig({...ldapConfig, bind_password: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Base de recherche</label>
                <input
                  type="text"
                  value={ldapConfig.search_base}
                  onChange={(e) => setLdapConfig({...ldapConfig, search_base: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  placeholder="CN=Users,DC=domain,DC=local"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Attribut nom d'utilisateur</label>
                  <input
                    type="text"
                    value={ldapConfig.username_attribute}
                    onChange={(e) => setLdapConfig({...ldapConfig, username_attribute: e.target.value})}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Attribut email</label>
                  <input
                    type="text"
                    value={ldapConfig.email_attribute}
                    onChange={(e) => setLdapConfig({...ldapConfig, email_attribute: e.target.value})}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                    required
                  />
                </div>
              </div>
              <div className="flex gap-2 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-purple-600 hover:bg-purple-700 py-2 rounded-lg"
                >
                  Sauvegarder
                </button>
                <button
                  type="button"
                  onClick={() => setShowLdapConfig(false)}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 rounded-lg"
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

// Certificate Management Component
const CertificateManager = ({ serverId, serverName }) => {
  const [certInfo, setCertInfo] = useState(null);
  const [showGenerate, setShowGenerate] = useState(false);
  const [certData, setCertData] = useState({
    cert_type: 'self_signed',
    domain: '',
    email: '',
    organization: 'Linux Management System',
    country: 'US'
  });

  useEffect(() => {
    if (serverId) {
      fetchCertInfo();
    }
  }, [serverId]);

  const fetchCertInfo = async () => {
    try {
      const response = await axios.get(`${API}/certificates/${serverId}`);
      setCertInfo(response.data);
    } catch (error) {
      // No certificate exists
      setCertInfo(null);
    }
  };

  const generateCertificate = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API}/certificates/generate`, {
        server_id: serverId,
        ...certData
      });
      alert('Certificat généré avec succès !');
      setShowGenerate(false);
      fetchCertInfo();
    } catch (error) {
      alert('Erreur lors de la génération: ' + (error.response?.data?.detail || error.message));
    }
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold">Certificats HTTPS</h3>
        <button
          onClick={() => setShowGenerate(true)}
          className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-sm"
        >
          📜 Générer Certificat
        </button>
      </div>

      {certInfo ? (
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Type:</span>
              <span className="ml-2 text-white">{certInfo.type}</span>
            </div>
            <div>
              <span className="text-gray-400">Domaine:</span>
              <span className="ml-2 text-white">{certInfo.domain}</span>
            </div>
            <div>
              <span className="text-gray-400">Créé:</span>
              <span className="ml-2 text-white">{new Date(certInfo.created_at).toLocaleDateString()}</span>
            </div>
            <div>
              <span className="text-gray-400">Expire:</span>
              <span className="ml-2 text-white">{new Date(certInfo.expires_at).toLocaleDateString()}</span>
            </div>
          </div>
          <div className="text-sm">
            <span className="text-gray-400">Organisation:</span>
            <span className="ml-2 text-white">{certInfo.organization}</span>
          </div>
        </div>
      ) : (
        <p className="text-gray-400 text-sm">Aucun certificat configuré</p>
      )}

      {/* Generate Certificate Modal */}
      {showGenerate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-96">
            <h3 className="text-xl font-bold mb-4">Générer Certificat SSL</h3>
            <form onSubmit={generateCertificate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Type de certificat</label>
                <select
                  value={certData.cert_type}
                  onChange={(e) => setCertData({...certData, cert_type: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                >
                  <option value="self_signed">Auto-signé (1 an)</option>
                  <option value="lets_encrypt">Let's Encrypt (bientôt)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Domaine/IP</label>
                <input
                  type="text"
                  value={certData.domain}
                  onChange={(e) => setCertData({...certData, domain: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  placeholder="example.com or 192.168.1.100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Organisation</label>
                <input
                  type="text"
                  value={certData.organization}
                  onChange={(e) => setCertData({...certData, organization: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Pays (code 2 lettres)</label>
                <input
                  type="text"
                  value={certData.country}
                  onChange={(e) => setCertData({...certData, country: e.target.value})}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  maxLength="2"
                />
              </div>
              <div className="flex gap-2 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-green-600 hover:bg-green-700 py-2 rounded-lg"
                >
                  Générer
                </button>
                <button
                  type="button"
                  onClick={() => setShowGenerate(false)}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 rounded-lg"
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

// Main Dashboard Component
const Dashboard = () => {
  const [servers, setServers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState('all');
  const [showAddServer, setShowAddServer] = useState(false);
  const [selectedServer, setSelectedServer] = useState(null);
  const [systemInfo, setSystemInfo] = useState({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const { user, logout, isAdmin } = useAuth();

  // New server form state
  const [newServer, setNewServer] = useState({
    name: '',
    hostname: '',
    port: 22,
    username: '',
    password: '',
    ssh_key: '',
    group: 'default',
    description: '',
    https_enabled: false,
    https_port: 443
  });

  useEffect(() => {
    if (activeTab === 'dashboard') {
      fetchServers();
      fetchGroups();
      
      // Auto-refresh system info every 30 seconds
      const interval = setInterval(() => {
        if (selectedServer) {
          fetchSystemInfo(selectedServer.id);
        }
      }, 30000);

      return () => clearInterval(interval);
    }
  }, [selectedServer, activeTab]);

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
        description: '',
        https_enabled: false,
        https_port: 443
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

  if (loading && activeTab === 'dashboard') {
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
          <div className="flex items-center space-x-4">
            <div className="flex space-x-2">
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`px-4 py-2 rounded-lg transition-colors ${
                  activeTab === 'dashboard' ? 'bg-blue-600' : 'bg-gray-600 hover:bg-gray-700'
                }`}
              >
                🖥️ Serveurs
              </button>
              {isAdmin && (
                <button
                  onClick={() => setActiveTab('users')}
                  className={`px-4 py-2 rounded-lg transition-colors ${
                    activeTab === 'users' ? 'bg-blue-600' : 'bg-gray-600 hover:bg-gray-700'
                  }`}
                >
                  👥 Utilisateurs
                </button>
              )}
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-300">
                {user.username} ({user.role})
              </div>
              <button
                onClick={logout}
                className="text-sm text-red-400 hover:text-red-300"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Content */}
      {activeTab === 'users' && isAdmin ? (
        <div className="p-6">
          <UserManagement />
        </div>
      ) : (
        <div className="flex">
          {/* Sidebar - Server List */}
          <div className="w-80 bg-gray-800 border-r border-gray-700 h-screen overflow-y-auto">
            {/* Group Filter */}
            <div className="p-4 border-b border-gray-700">
              <div className="flex justify-between items-center mb-2">
                <select
                  value={selectedGroup}
                  onChange={(e) => setSelectedGroup(e.target.value)}
                  className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 mr-2"
                >
                  <option value="all">Tous les groupes ({servers.length})</option>
                  {groups.map(group => (
                    <option key={group.name} value={group.name}>
                      {group.name} ({group.count})
                    </option>
                  ))}
                </select>
                {isAdmin && (
                  <button
                    onClick={() => setShowAddServer(true)}
                    className="bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded transition-colors text-sm"
                  >
                    +
                  </button>
                )}
              </div>
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
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs bg-gray-600 px-2 py-1 rounded">
                          {server.group}
                        </span>
                        {server.https_enabled && (
                          <span className="text-xs bg-green-600 px-2 py-1 rounded">
                            🔒 HTTPS
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-sm font-medium ${getStatusColor(server.status)}`}>
                        ● {server.status}
                      </div>
                      {isAdmin && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteServer(server.id);
                          }}
                          className="text-red-400 hover:text-red-300 text-xs mt-1"
                        >
                          Supprimer
                        </button>
                      )}
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

                {/* Certificate Management (Admin only) */}
                {isAdmin && (
                  <div className="mb-6">
                    <CertificateManager serverId={selectedServer.id} serverName={selectedServer.name} />
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
      )}

      {/* Add Server Modal */}
      {showAddServer && isAdmin && (
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
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={newServer.https_enabled}
                    onChange={(e) => setNewServer({...newServer, https_enabled: e.target.checked})}
                    className="mr-2"
                  />
                  Activer HTTPS
                </label>
              </div>
              {newServer.https_enabled && (
                <div>
                  <label className="block text-sm font-medium mb-1">Port HTTPS</label>
                  <input
                    type="number"
                    value={newServer.https_port}
                    onChange={(e) => setNewServer({...newServer, https_port: parseInt(e.target.value)})}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                  />
                </div>
              )}
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

const App = () => {
  return (
    <AuthProvider>
      <AuthComponent />
    </AuthProvider>
  );
};

const AuthComponent = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-xl">Chargement...</div>
      </div>
    );
  }

  return user ? <Dashboard /> : <Login />;
};

export default App;
# 🐧 Installation du Gestionnaire Linux Multi-Serveurs

## Table des matières
- [Prérequis](#prérequis)
- [Installation Ubuntu/Debian](#installation-ubuntudebian)
- [Installation CentOS/RHEL/Rocky Linux](#installation-centosrhelrocky-linux)
- [Installation Fedora](#installation-fedora)
- [Installation Arch Linux](#installation-arch-linux)
- [Installation openSUSE](#installation-opensuse)
- [Configuration](#configuration)
- [Premier démarrage](#premier-démarrage)
- [Dépannage](#dépannage)

---

## Prérequis

### Matériel recommandé
- **RAM** : Minimum 2GB, recommandé 4GB+
- **CPU** : 2 cores minimum  
- **Stockage** : 10GB d'espace libre minimum
- **Réseau** : Connexion internet pour l'installation

### Logiciels requis
- **Node.js** 18+ et **yarn**
- **Python** 3.8+ et **pip**
- **MongoDB** 4.4+
- **Git**

---

## Installation Ubuntu/Debian

### 1. Mise à jour du système
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Installation des dépendances système
```bash
# Installation des paquets de base
sudo apt install -y curl wget git build-essential python3 python3-pip python3-venv

# Installation de Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Installation de Yarn
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt update && sudo apt install -y yarn

# Installation de MongoDB
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update && sudo apt install -y mongodb-org

# Installation de supervisor
sudo apt install -y supervisor
```

### 3. Démarrage des services
```bash
# Démarrage et activation de MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Vérification du statut
sudo systemctl status mongod
```

### 4. Clonage et installation de l'application
```bash
# Clonage du repository
git clone https://github.com/votre-username/linux-manager.git
cd linux-manager

# Installation des dépendances backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Installation des dépendances frontend
cd ../frontend
yarn install

# Retour au répertoire racine
cd ..
```

---

## Installation CentOS/RHEL/Rocky Linux

### 1. Mise à jour du système
```bash
sudo dnf update -y
# Ou pour CentOS 7: sudo yum update -y
```

### 2. Installation des dépendances système
```bash
# Installation des paquets de base
sudo dnf install -y curl wget git gcc gcc-c++ make python3 python3-pip python3-devel

# Installation de Node.js 18+
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo dnf install -y nodejs

# Installation de Yarn
curl -sL https://dl.yarnpkg.com/rpm/yarn.repo -o /tmp/yarn.repo
sudo mv /tmp/yarn.repo /etc/yum.repos.d/yarn.repo
sudo dnf install -y yarn

# Installation de MongoDB
sudo tee /etc/yum.repos.d/mongodb-org-6.0.repo << 'EOF'
[mongodb-org-6.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/6.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-6.0.asc
EOF

sudo dnf install -y mongodb-org

# Installation de supervisor
sudo dnf install -y supervisor
```

### 3. Configuration du pare-feu
```bash
# Ouverture des ports nécessaires
sudo firewall-cmd --permanent --add-port=3000/tcp  # Frontend
sudo firewall-cmd --permanent --add-port=8001/tcp  # Backend
sudo firewall-cmd --permanent --add-port=27017/tcp # MongoDB (optionnel)
sudo firewall-cmd --reload
```

### 4. Démarrage des services
```bash
# Démarrage et activation de MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Démarrage de supervisor
sudo systemctl start supervisord
sudo systemctl enable supervisord
```

---

## Installation Fedora

### 1. Mise à jour du système
```bash
sudo dnf update -y
```

### 2. Installation des dépendances système
```bash
# Installation des paquets de base
sudo dnf install -y curl wget git gcc gcc-c++ make python3 python3-pip python3-devel nodejs yarn

# Installation de MongoDB (via repository officiel)
sudo tee /etc/yum.repos.d/mongodb-org-6.0.repo << 'EOF'
[mongodb-org-6.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/6.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-6.0.asc
EOF

sudo dnf install -y mongodb-org supervisor
```

### 3. Configuration SELinux (si activé)
```bash
# Vérification du statut SELinux
sestatus

# Si SELinux est activé, configuration des contextes
sudo setsebool -P httpd_can_network_connect 1
sudo semanage port -a -t http_port_t -p tcp 3000
sudo semanage port -a -t http_port_t -p tcp 8001
```

---

## Installation Arch Linux

### 1. Mise à jour du système
```bash
sudo pacman -Syu
```

### 2. Installation des dépendances système
```bash
# Installation des paquets de base
sudo pacman -S --needed base-devel curl wget git python python-pip nodejs yarn mongodb-bin supervisor

# Ou installation de MongoDB via AUR
yay -S mongodb-bin
# Ou avec pamac: pamac install mongodb-bin
```

### 3. Démarrage des services
```bash
# Activation et démarrage de MongoDB
sudo systemctl enable mongodb
sudo systemctl start mongodb

# Activation de supervisor
sudo systemctl enable supervisord
sudo systemctl start supervisord
```

---

## Installation openSUSE

### 1. Mise à jour du système
```bash
sudo zypper refresh && sudo zypper update -y
```

### 2. Installation des dépendances système
```bash
# Installation des paquets de base
sudo zypper install -y curl wget git gcc gcc-c++ make python3 python3-pip python3-devel

# Installation de Node.js et Yarn
sudo zypper install -y nodejs18 npm
sudo npm install -g yarn

# Installation de MongoDB
sudo zypper addrepo --gpgcheck --refresh https://download.opensuse.org/repositories/server:database/openSUSE_Leap_15.4/server:database.repo
sudo zypper refresh && sudo zypper install -y mongodb

# Installation de supervisor
sudo zypper install -y python3-supervisor
```

---

## Configuration

### 1. Configuration MongoDB
```bash
# Édition du fichier de configuration MongoDB
sudo nano /etc/mongod.conf

# Configuration recommandée:
# storage:
#   dbPath: /var/lib/mongo
# systemLog:
#   destination: file
#   logAppend: true
#   path: /var/log/mongodb/mongod.log
# net:
#   port: 27017
#   bindIp: 127.0.0.1

# Redémarrage de MongoDB
sudo systemctl restart mongod
```

### 2. Configuration de l'application
```bash
# Copie des fichiers de configuration
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Édition de la configuration backend
nano backend/.env
```

**Configuration backend (.env) :**
```bash
MONGO_URL="mongodb://localhost:27017"
DB_NAME="linux_manager"
JWT_SECRET="your-super-secret-jwt-key-change-in-production-use-strong-key-here"
```

**Configuration frontend (.env) :**
```bash
REACT_APP_BACKEND_URL=http://your-server-ip:8001
WDS_SOCKET_PORT=443
```

### 3. Configuration Supervisor
```bash
# Création des fichiers de configuration Supervisor
sudo mkdir -p /etc/supervisor/conf.d

# Configuration backend
sudo tee /etc/supervisor/conf.d/linux-manager-backend.conf << 'EOF'
[program:linux-manager-backend]
command=/path/to/linux-manager/backend/venv/bin/python -m uvicorn server:app --host 0.0.0.0 --port 8001
directory=/path/to/linux-manager/backend
user=www-data
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/linux-manager-backend.err.log
stdout_logfile=/var/log/supervisor/linux-manager-backend.out.log
environment=PATH="/path/to/linux-manager/backend/venv/bin"
EOF

# Configuration frontend
sudo tee /etc/supervisor/conf.d/linux-manager-frontend.conf << 'EOF'
[program:linux-manager-frontend]
command=yarn start
directory=/path/to/linux-manager/frontend
user=www-data
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/linux-manager-frontend.err.log
stdout_logfile=/var/log/supervisor/linux-manager-frontend.out.log
environment=PATH="/usr/bin:/bin:/usr/local/bin",PORT="3000"
EOF

# Rechargement de la configuration Supervisor
sudo supervisorctl reread
sudo supervisorctl update
```

---

## Premier démarrage

### 1. Démarrage des services
```bash
# Démarrage des applications via Supervisor
sudo supervisorctl start linux-manager-backend
sudo supervisorctl start linux-manager-frontend

# Vérification du statut
sudo supervisorctl status
```

### 2. Vérification de l'installation
```bash
# Test de l'API backend
curl http://localhost:8001/api/

# Vérification des logs
sudo supervisorctl tail -f linux-manager-backend
sudo supervisorctl tail -f linux-manager-frontend
```

### 3. Accès à l'interface
- **URL** : `http://your-server-ip:3000`
- **Utilisateur par défaut** : `admin`
- **Mot de passe par défaut** : `admin123`

### 4. Configuration initiale
1. Connectez-vous avec le compte admin par défaut
2. Changez le mot de passe administrateur
3. Configurez LDAP si nécessaire (onglet Utilisateurs → Config LDAP)
4. Ajoutez vos premiers serveurs Linux

---

## Dépannage

### Problèmes courants

#### 1. MongoDB ne démarre pas
```bash
# Vérification des logs
sudo tail -f /var/log/mongodb/mongod.log

# Vérification des permissions
sudo chown -R mongodb:mongodb /var/lib/mongo
sudo chown mongodb:mongodb /tmp/mongodb-*.sock

# Redémarrage
sudo systemctl restart mongod
```

#### 2. Erreur de ports occupés
```bash
# Vérification des ports utilisés
sudo netstat -tulpn | grep :3000
sudo netstat -tulpn | grep :8001

# Arrêt des processus si nécessaire
sudo kill -9 $(sudo lsof -t -i:3000)
sudo kill -9 $(sudo lsof -t -i:8001)
```

#### 3. Erreurs de permissions
```bash
# Attribution des permissions correctes
sudo chown -R $USER:$USER /path/to/linux-manager
chmod +x /path/to/linux-manager/backend/venv/bin/python
```

#### 4. Problèmes de dépendances Python
```bash
# Réinstallation de l'environnement virtuel
cd backend
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### 5. Problèmes de dépendances Node.js
```bash
# Nettoyage et réinstallation
cd frontend
rm -rf node_modules package-lock.json yarn.lock
yarn install
```

### Logs utiles
```bash
# Logs Supervisor
sudo tail -f /var/log/supervisor/supervisord.log
sudo tail -f /var/log/supervisor/linux-manager-*.log

# Logs MongoDB
sudo tail -f /var/log/mongodb/mongod.log

# Logs système
sudo journalctl -u mongod -f
sudo journalctl -u supervisord -f
```

### Support
- **Issues GitHub** : [Lien vers les issues]
- **Documentation** : [Lien vers la documentation]
- **Email** : support@example.com

---

## Sécurité

### Recommandations de production

1. **Changez le mot de passe admin par défaut**
2. **Configurez un pare-feu** (ufw, firewalld, iptables)
3. **Utilisez HTTPS** avec des certificats SSL valides
4. **Activez l'authentification MongoDB** si accessible depuis l'extérieur
5. **Limitez l'accès SSH** aux serveurs managés
6. **Configurez des sauvegardes** régulières de la base de données
7. **Mettez à jour régulièrement** le système et les dépendances

### Configuration SSL/HTTPS
```bash
# Installation de Nginx comme reverse proxy
sudo apt install nginx  # Ubuntu/Debian
sudo dnf install nginx  # CentOS/RHEL/Fedora

# Configuration basique Nginx
sudo tee /etc/nginx/sites-available/linux-manager << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location /api {
        proxy_pass http://localhost:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Activation du site
sudo ln -s /etc/nginx/sites-available/linux-manager /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

**🎉 Installation terminée ! Votre gestionnaire Linux multi-serveurs est maintenant opérationnel.**

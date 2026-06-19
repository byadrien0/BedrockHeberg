# ServerAura

ServerAura est un panneau d'administration web pour créer, configurer et exploiter plusieurs serveurs Minecraft Bedrock Dedicated Server depuis une interface unique.

Le projet fonctionne localement sous Windows et Linux, ainsi que dans un conteneur Docker. Il automatise l'installation officielle de Bedrock, sépare les données de chaque instance et fournit les outils nécessaires à l'exploitation quotidienne sans modifier les fichiers à la main.

## Fonctionnalités

### Gestion des serveurs

- création, modification et suppression de plusieurs instances ;
- installation automatique du serveur Bedrock officiel sous Windows et Linux ;
- détection des états `Non installé`, `Installation`, `Prêt` et `Erreur` ;
- premier démarrage guidé avant d'afficher les fonctions dépendantes du monde ;
- démarrage, arrêt et redémarrage avec verrouillage des actions incompatibles ;
- détection de la version installée et mise à jour avec sauvegarde préalable ;
- auto-start configurable pour chaque instance.

### Tableau de bord

- statut et progression en temps réel ;
- version, uptime, joueurs et espace disque utilisé ;
- allocation RAM et CPU configurée ;
- dernière sauvegarde et dernière erreur ;
- adresse locale, adresse publique et état du port UDP ;
- copie rapide de l'adresse de connexion.

### Performances

ServerAura propose quatre profils :

| Profil | RAM | CPU | Affichage | Simulation |
| --- | ---: | ---: | ---: | ---: |
| Économie | 1 Go | 1 cœur | 12 chunks | 4 chunks |
| Équilibré | 2 Go | 2 cœurs | 24 chunks | 6 chunks |
| Performance | 4 Go | 4 cœurs | 32 chunks | 8 chunks |
| Personnalisé | configurable | configurable | configurable | configurable |

Le nombre de cœurs configure la propriété Bedrock `max-threads`. La RAM correspond au budget attribué à l'instance : Bedrock Dedicated Server étant un exécutable natif, il ne fournit pas d'option de limite mémoire stricte comparable à `-Xmx` sur Java.

### Console et fichiers

- console en temps réel via Server-Sent Events (SSE) ;
- historique des commandes ;
- recherche et filtrage des journaux ;
- explorateur avec fil d'Ariane et recherche ;
- création, édition, renommage et suppression ;
- import et téléchargement de fichiers ;
- confirmation avant les opérations destructives.

### Mondes, joueurs et sauvegardes

- import et export de fichiers `.mcworld` ;
- duplication, activation et réinitialisation d'un monde ;
- restauration depuis une sauvegarde ;
- joueurs connectés et expulsion ;
- liste blanche et permissions visiteur, membre ou opérateur ;
- sauvegardes manuelles et automatiques ;
- fréquence et rétention configurables ;
- suppression automatique des sauvegardes les plus anciennes ;
- origine, date et taille affichées dans l'interface.

### Administration et sécurité

- comptes administrateur et lecture seule ;
- authentification à double facteur TOTP facultative ;
- sessions HTTP protégées et jetons CSRF ;
- cookies sécurisés en production ;
- historique persistant des opérations ;
- file d'attente empêchant les doubles démarrages et opérations incompatibles ;
- validation des chemins pour empêcher la sortie des dossiers gérés.

## Prérequis

- Node.js 20 ou supérieur ;
- npm ;
- Windows 10/11 ou une distribution Linux compatible avec Bedrock Dedicated Server ;
- un port UDP accessible pour permettre aux joueurs de rejoindre le serveur ;
- Microsoft Edge ou Chromium uniquement pour exécuter les tests navigateur.

Le binaire Minecraft n'est pas versionné dans ce dépôt. ServerAura télécharge l'archive officielle au moment de l'installation.

## Installation locale

```powershell
git clone https://github.com/byadrien0/ServerAura.git
cd ServerAura
npm install
```

Crée ensuite un fichier `.env` à partir de `.env.example`, ou définis les variables directement dans ton terminal :

```powershell
$env:PORT="3001"
$env:ADMIN_PASSWORD="change-moi"
$env:SESSION_SECRET="une-longue-valeur-aleatoire"
$env:AUTO_START="false"
npm start
```

Ouvre `http://127.0.0.1:3001`, connecte-toi avec l'utilisateur `admin`, crée une instance puis utilise le bouton **Installer**.

Sous Linux ou macOS pour le panneau :

```bash
PORT=3001 \
ADMIN_PASSWORD='change-moi' \
SESSION_SECRET='une-longue-valeur-aleatoire' \
AUTO_START=false \
npm start
```

Minecraft Bedrock Dedicated Server n'est officiellement fourni que pour Windows et certaines distributions Linux. Le panneau peut être développé ailleurs, mais le serveur de jeu nécessite une plateforme prise en charge.

## Configuration

| Variable | Obligatoire | Valeur par défaut | Description |
| --- | --- | --- | --- |
| `PORT` | non | `3001` | Port HTTP du panneau |
| `ADMIN_PASSWORD` | en production | généré en développement | Mot de passe du premier compte `admin` |
| `SESSION_SECRET` | en production | généré en développement | Secret de signature des sessions |
| `AUTO_START` | non | `true` | Démarre automatiquement les instances configurées |
| `SESSION_DIR` | non | dépend de l'environnement | Stockage persistant des sessions |
| `SERVER_DIR` | non | dossier local ou `/data` | Dossier de l'instance principale historique |
| `SERVERS_DIR` | non | dossier local ou `/data/servers` | Racine des instances |
| `BACKUP_ROOT` | non | dossier local ou `/data/backups` | Racine des sauvegardes |
| `SEED_DIR` | non | racine du projet | Modèle initial facultatif |
| `PUBLIC_IP` | non | vide | Adresse publique affichée dans le panneau |
| `BDS_DOWNLOAD_URL` | non | manifeste officiel | Archive Bedrock imposée manuellement |

Ne publie jamais `.env`, les secrets de session, les mondes ou les sauvegardes dans Git.

## Organisation des données

```text
config/servers.json       registre des instances
servers/<identifiant>/    binaire, configuration et mondes d'une instance
backups/<identifiant>/    sauvegardes ZIP de l'instance
.panel/                   comptes, sessions et historique local
src/                      application Node.js
test/                     tests métier, API et navigateur
```

Ces dossiers d'exécution sont exclus par `.gitignore`.

## Scripts

```bash
npm start                 # démarre ServerAura
npm run check             # vérifie la syntaxe JavaScript
npm test                  # exécute les tests métier
npm run test:api          # teste le parcours API principal
npm run test:browser      # teste les parcours desktop et mobile
```

Les tests API et navigateur utilisent par défaut `http://127.0.0.1:3001`, l'utilisateur `admin` et le mot de passe `admin`. Tu peux remplacer l'adresse et le mot de passe avec `TEST_BASE_URL` et `TEST_ADMIN_PASSWORD`.

## Docker

```bash
docker build -t serveraura .
docker run --rm \
  -p 3000:3000/tcp \
  -p 19132:19132/udp \
  -v serveraura-data:/data \
  -e PORT=3000 \
  -e ADMIN_PASSWORD='change-moi' \
  -e SESSION_SECRET='une-longue-valeur-aleatoire' \
  serveraura
```

Chaque serveur supplémentaire doit utiliser un port UDP distinct et ce port doit également être exposé par l'hôte.

## Déploiement Railway

Le dépôt contient un `Dockerfile` et un fichier `railway.json`. Monte impérativement un volume persistant sur `/data`, puis configure au minimum `ADMIN_PASSWORD` et `SESSION_SECRET`.

Railway expose facilement le panneau HTTP, mais l'accès public à Minecraft nécessite une exposition UDP. Vérifie que l'offre et la configuration réseau choisies prennent en charge les ports UDP avant de retenir cette plateforme pour le serveur de jeu.

Les instructions détaillées sont disponibles dans [README_RAILWAY.md](README_RAILWAY.md).

## Architecture

- `src/server.js` : routes HTTP, API, authentification et interface web ;
- `src/multi-server-manager.js` : registre et cycle de vie des instances ;
- `src/bedrock-manager.js` : processus Bedrock, fichiers, mondes, réseau et sauvegardes ;
- `src/user-store.js` : comptes, rôles et TOTP ;
- `src/activity-store.js` : historique d'activité persistant.

L'interface utilise du HTML/CSS/JavaScript natif servi par Express. Les événements de console et d'opérations transitent par SSE, ce qui évite le rafraîchissement périodique agressif.

## Limites connues

- l'accessibilité publique dépend du routage UDP de l'hébergeur et du pare-feu ;
- le budget RAM n'est pas une limite système stricte du processus Bedrock ;
- certaines modifications de performances nécessitent un redémarrage ;
- les données sont locales par défaut et doivent être placées sur un volume persistant en production.

## Contribution

1. Crée une branche depuis `main`.
2. Garde les modifications ciblées et compatibles Windows/Linux.
3. Exécute `npm run check`, `npm test` et les tests navigateur concernés.
4. Ouvre une pull request avec le comportement testé et les éventuels changements de configuration.

## Avertissement

ServerAura est un projet communautaire indépendant. Minecraft et Bedrock Dedicated Server appartiennent à Microsoft/Mojang. L'utilisation du serveur officiel reste soumise aux conditions applicables de Microsoft et de Minecraft.

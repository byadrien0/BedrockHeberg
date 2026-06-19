# Bedrock Railway Panel

Cette app lance et gere plusieurs serveurs Minecraft Bedrock Dedicated Server avec une interface web Node.js.

## Fonctions

- creation, modification et suppression de serveurs;
- demarrage, arret, redemarrage par serveur;
- console Bedrock par serveur;
- console temps reel SSE, recherche et historique des commandes;
- edition de `server.properties` par serveur;
- sauvegardes manuelles et automatiques avec retention;
- joueurs, liste blanche et permissions Bedrock;
- import, export, duplication, activation et restauration de mondes;
- upload, telechargement et renommage de fichiers;
- comptes administrateur/lecture seule et TOTP facultatif;
- historique persistant des operations;
- reinstallation du binaire Bedrock Linux officiel;
- copie initiale optionnelle depuis un dossier seed vers un volume persistant.

## Variables Railway

Ajoute au minimum:

```text
ADMIN_PASSWORD=un-mot-de-passe-solide
SESSION_SECRET=une-longue-valeur-random
AUTO_START=true
SERVER_DIR=/data/servers/principal
SERVERS_DIR=/data/servers
BACKUP_ROOT=/data/backups
SEED_DIR=/opt/bedrock-seed
PUBLIC_IP=adresse-publique-optionnelle
```

Monte un volume Railway sur `/data`, sinon les mondes, la liste des serveurs et les sauvegardes peuvent disparaitre a chaque redeploiement.

Le repo ne versionne plus le serveur Bedrock extrait, les mondes, les packs vanilla ni les sauvegardes. Ces fichiers sont generes, telecharges ou stockes sur le volume persistant.

## Reseau

L'interface web utilise le port HTTP fourni par Railway via `PORT`.

Minecraft Bedrock utilise UDP. Chaque serveur doit avoir son propre port, par exemple `19132`, `19134`, `19136`. Le Dockerfile declare `19132` et `19133`, mais Railway Public Networking expose surtout HTTP/HTTPS. Si ton projet Railway ne propose pas d'exposition UDP publique, les joueurs ne pourront pas rejoindre directement les serveurs Bedrock depuis Railway. Dans ce cas, utilise un hebergement qui expose UDP publiquement, ou ajoute un tunnel UDP compatible Bedrock.

## Deploiement

1. Mets ce dossier dans un repo Git.
2. Cree un nouveau service Railway depuis ce repo.
3. Ajoute un volume monte sur `/data`.
4. Ajoute les variables ci-dessus.
5. Genere le domaine Railway pour l'interface web.
6. Connecte-toi a l'interface avec `ADMIN_PASSWORD`.

Le premier compte est `admin`. Les comptes suivants et la 2FA se gerent depuis l'onglet `Comptes`.

## Tests

```text
npm test
npm run test:api
npm run test:browser
```

Les tests API et navigateur attendent le panel sur `http://127.0.0.1:3001` avec le mot de passe local `admin`, sauf si `TEST_BASE_URL` et `TEST_ADMIN_PASSWORD` sont definis.

Au premier demarrage, l'app cree un serveur `principal`, copie les donnees presentes dans `SEED_DIR` si ce dossier existe, telecharge le serveur Bedrock Linux officiel, puis lance les serveurs en auto-start.

Les nouveaux serveurs crees depuis l'interface sont places dans `/data/servers/<id>` et leurs sauvegardes dans `/data/backups/<id>`.

## Depot Git

Garde dans Git le panel Node.js, Docker, la doc et les exemples d'environnement. Garde hors Git:

- `bedrock_server` / `bedrock_server.exe`;
- `behavior_packs`, `resource_packs`, `definitions`, `worlds`, `world_templates`;
- `servers`, `backups`, `.panel`;
- fichiers runtime Bedrock comme `server.properties`, `allowlist.json`, `permissions.json`.

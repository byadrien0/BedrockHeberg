# Audit ServerAura

## Constats

- Le depot contenait presque uniquement des artefacts Bedrock generes: packs vanilla, definitions, mondes, fichiers de serveur et documentation HTML officielle. Cela representait 8 937 fichiers sur 8 955 suivis par Git.
- Le Dockerfile copiait ces artefacts dans l'image, ce qui rendait les builds plus lourds et melangeait code applicatif et donnees runtime.
- En production, l'application pouvait demarrer avec un `ADMIN_PASSWORD` et un `SESSION_SECRET` generes en memoire. C'est pratique en local, mais fragile en hebergement.
- Le serveur local par defaut utilisait la racine du projet comme dossier serveur, ce qui expose trop de fichiers au gestionnaire de fichiers du panel.
- Aucune vulnerabilite npm n'a ete detectee avec `npm audit --audit-level=moderate`.

## Corrections appliquees

- Retrait de l'index Git des artefacts Bedrock lourds sans les supprimer du disque local.
- Ajout des dossiers/fichiers runtime Bedrock dans `.gitignore` et `.dockerignore`.
- Allegement du Dockerfile: l'image contient le panel, puis le binaire Bedrock officiel adapte au systeme est telecharge au demarrage.
- Ajout d'un script `npm run check` pour valider la syntaxe des fichiers Node.
- Refus de demarrage en production si `ADMIN_PASSWORD` ou `SESSION_SECRET` manquent.
- Ajout d'en-tetes HTTP de base et d'une limite simple sur les echecs de connexion.
- Isolation des instances locales par defaut dans `servers/principal`.

## Ameliorations conseillees ensuite

- Extraire le HTML/CSS/JS inline de `src/server.js` vers des fichiers `views/` et `public/` pour faciliter le design.
- Ajouter une couche CSRF sur les routes `POST`, `PUT`, `PATCH` et `DELETE`.
- Ajouter des tests automatises pour les operations fichiers, sauvegardes et validation des ports.
- Ajouter une page de configuration dediee aux variables et au statut UDP pour rendre le deploiement Railway plus explicite.
- Envisager un stockage de session persistant si plusieurs replicas sont utilises.

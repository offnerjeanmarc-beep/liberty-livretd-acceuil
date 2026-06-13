# Déploiement cPanel - Conciergerie Liberty

## Pré-requis cPanel

- Domaine ou sous-domaine prêt
- Fonction cPanel **Setup Node.js App** activée
- Node.js 18.17+ minimum
- Base MySQL créée
- Utilisateur MySQL relié à la base
- HTTPS actif sur le domaine

## Base de données

Créer dans cPanel :

1. une base MySQL, par exemple `cpaneluser_liberty`
2. un utilisateur MySQL, par exemple `cpaneluser_liberty_app`
3. un mot de passe fort
4. associer l'utilisateur à la base avec les droits nécessaires

Droits requis :

```text
SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX
```

## Variables d'environnement

Dans **Setup Node.js App**, ajouter :

```text
NODE_ENV=production
BASE_URL=https://votre-domaine.fr
DATABASE_URL=mysql://USER:PASSWORD@localhost:3306/DATABASE
SESSION_SECRET=valeur-longue-aleatoire
ADMIN_PASSWORD=mot-de-passe-admin-fort
FORCE_HTTPS=true
OPENAI_MODEL=gpt-5.5
DB_CONNECTION_LIMIT=10
HOST=127.0.0.1
```

Ne jamais mettre ces valeurs dans GitHub.

## Configuration Node.js App

Dans cPanel :

```text
Application mode: Production
Application root: dossier du projet
Application URL: domaine ou sous-domaine
Application startup file: server.js
Passenger log file: logs/passenger.log
```

Puis exécuter :

```bash
npm install --omit=dev
```

Et redémarrer l'application depuis cPanel.

## Déploiement depuis GitHub

Option recommandée :

1. Cloner le dépôt GitHub dans le dossier applicatif cPanel.
2. Vérifier que `.env` n'est pas dans le dépôt.
3. Définir les variables dans cPanel.
4. Lancer `npm install --omit=dev`.
5. Redémarrer l'application.

## Validation après déploiement

Vérifier :

- `/` répond
- `/sejour/appartement-cathedrale` affiche le sas sécurisé
- `/admin` affiche le login admin
- login admin fonctionne
- tables MySQL créées automatiquement
- QR Wi-Fi affiché
- CRM fonctionne
- analytics fonctionne
- Assistant IA répond ou affiche son message d'indisponibilité
- `/mentions-legales` et `/confidentialite` répondent

## Sauvegarde

Créer un dossier non public `backups/`.

Commande type :

```bash
mysqldump --single-transaction --routines --triggers \
  -u USER -p DATABASE > backups/liberty_$(date +%F_%H-%M).sql
```

## Restauration

```bash
mysql -u USER -p DATABASE < backups/liberty_YYYY-MM-DD_HH-MM.sql
```

Avant restauration :

1. mettre l'application en maintenance
2. sauvegarder la base actuelle
3. restaurer
4. redémarrer Node.js App
5. vérifier les parcours voyageur/admin

## Points sensibles

- Ne pas utiliser SQLite en production.
- Ne pas pousser `.env` sur GitHub.
- Ne pas exposer `DATABASE_URL`, clés OpenAI ou mots de passe dans le front.
- Utiliser HTTPS avant ouverture aux voyageurs.

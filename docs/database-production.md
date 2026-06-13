# Base de données production - Conciergerie Liberty

## Décision

MySQL est la base principale en production.

SQLite reste autorisé uniquement pour :

- développement local
- tests rapides
- prototype temporaire

## Configuration par environnement

L'application choisit automatiquement le moteur avec `DATABASE_URL`.

Local par défaut, si `DATABASE_URL` est absent :

```text
sqlite:data/liberty.sqlite
```

Production MySQL :

```text
DATABASE_URL=mysql://USER:PASSWORD@HOST:3306/DATABASE
```

Exemple sans vrais identifiants :

```text
DATABASE_URL=mysql://liberty_app:change-me@localhost:3306/liberty_production
```

Les secrets MySQL doivent rester dans `.env` ou dans les variables d'environnement cPanel. Ils ne sont jamais injectés dans le front.

## Initialisation

Au démarrage, l'application :

1. lit `DATABASE_URL`
2. ouvre SQLite ou MySQL
3. crée les tables manquantes
4. applique les colonnes manquantes
5. conserve les données existantes

Le code source ne change pas entre local et production.

## Migrations

Références SQL :

- `docs/migrations/001_mysql_initial.sql`
- `docs/migrations/001_sqlite_initial.sql`

Le serveur contient aussi une migration de démarrage idempotente pour éviter un déploiement fragile.

## Sauvegarde MySQL

Commande type :

```bash
mysqldump --single-transaction --routines --triggers \
  -u liberty_app -p liberty_production > backups/liberty_$(date +%F_%H-%M).sql
```

Bonnes pratiques :

- sauvegarde quotidienne automatisée
- conservation 30 jours minimum
- copie hors serveur
- test de restauration mensuel
- sauvegarde avant chaque migration

## Restauration MySQL

Commande type :

```bash
mysql -u liberty_app -p liberty_production < backups/liberty_YYYY-MM-DD_HH-MM.sql
```

Avant restauration :

1. mettre l'application en maintenance
2. sauvegarder l'état actuel
3. restaurer le dump
4. redémarrer l'application
5. vérifier admin, livrets, CRM, analytics et assistant IA

## Supervision minimale

À suivre :

- taille de la base
- nombre de connexions
- temps de réponse dashboard
- erreurs SQL
- croissance `analytics_events`
- croissance `chat_messages`
- sauvegardes réussies

## Production cPanel

Variables à définir côté cPanel Node.js :

```text
NODE_ENV=production
DATABASE_URL=mysql://USER:PASSWORD@HOST:3306/DATABASE
BASE_URL=https://domaine-final.fr
SESSION_SECRET=valeur-longue-aleatoire
FORCE_HTTPS=true
OPENAI_MODEL=gpt-5.5
```

Ne pas commiter `.env`.

# Architecture Liberty - Avant déploiement

## Principe

Une seule application sert tous les logements.

```text
/sejour/appartement-cathedrale
/sejour/studio-gare
/sejour/duplex-centre
```

Le `slug` dans l'URL identifie le logement. Le serveur charge ensuite les données correspondantes depuis la base centralisée.

## Données centralisées

Table `properties` :

- identité du logement
- URL unique
- mot de passe voyageur hashé
- image principale
- adresse et GPS
- clé API OpenAI du logement
- modèle OpenAI
- instructions Assistant IA Liberty
- données opérationnelles JSON

Table `service_requests` :

- demandes voyageurs
- type de demande
- logement concerné
- statut opérationnel

Table `chat_messages` :

- historique des échanges assistant/voyageur
- logement concerné

## Sécurité actuelle

- mot de passe différent par appartement
- mots de passe stockés en hash PBKDF2
- session voyageur signée par cookie HTTP-only
- session administration séparée
- clés OpenAI conservées côté serveur
- aucune clé OpenAI exposée dans le navigateur

Avant production, activer HTTPS et utiliser un `SESSION_SECRET` fort dans `.env`.

## Assistant IA Liberty

L'API `/api/chat/{slug}` :

1. vérifie que le voyageur est connecté au bon logement
2. charge les données du logement
3. assemble les instructions Liberty et le contexte opérationnel
4. appelle OpenAI côté serveur si une clé est renseignée
5. sinon répond avec le moteur local de secours

Les instructions finales que Liberty fournira avant déploiement doivent être renseignées dans le champ `Instructions Assistant IA` du panneau d'administration.

## Administration

URL locale :

```text
http://127.0.0.1:4173/admin
```

Fonctions :

- créer un logement
- générer une URL unique
- modifier toutes les données opérationnelles
- changer le mot de passe voyageur
- ajouter une clé OpenAI par logement
- modifier les instructions IA
- consulter les demandes du Centre de Services

## Modules prêts à raccorder

- services payants
- réservation directe
- programme fidélité
- espace propriétaire
- statistiques
- paiement options
- commission activités

## Arrêt projet demandé

Ne pas déployer tant que ces points ne sont pas validés :

- vraies informations logements
- vraies instructions IA Liberty
- vraies clés API OpenAI par logement
- nom de domaine final
- mode cPanel Node.js confirmé
- choix SQLite ou migration MySQL confirmé
- stratégie sauvegarde base confirmée
- dépôt GitHub validé

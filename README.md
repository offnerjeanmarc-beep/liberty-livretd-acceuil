# Conciergerie Liberty - Espace voyageurs dynamique

Application multi-logements pour gérer tous les livrets d'accueil Liberty depuis une seule structure technique.

## Lancement local

```powershell
npm.cmd start
```

Puis ouvrir :

```text
http://127.0.0.1:4173
```

En local, si `DATABASE_URL` est absent, la base SQLite est créée automatiquement dans `data/liberty.sqlite`.

En production, utiliser MySQL avec :

```text
DATABASE_URL=mysql://USER:PASSWORD@HOST:3306/DATABASE
```

SQLite ne doit pas être utilisé en production.

## Accès de test

Administration :

```text
URL : http://127.0.0.1:4173/admin
Mot de passe : ADMINLIBERTY2026
```

Espaces voyageurs :

```text
http://127.0.0.1:4173/sejour/appartement-cathedrale
Mot de passe : CATHEDRALE2026

http://127.0.0.1:4173/sejour/studio-gare
Mot de passe : GARE2026

http://127.0.0.1:4173/sejour/duplex-centre
Mot de passe : DUPLEX2026
```

## Fonctionnalités livrées

- URL unique par logement : `/sejour/slug-du-logement`
- Mot de passe sécurisé par appartement, hashé côté serveur
- Base centralisée des logements, informations opérationnelles, consignes IA, demandes voyageurs et historique chat
- Tables évolutives CRM, analytics, POI mutualisés par ville
- Configuration `DATABASE_URL` : SQLite local, MySQL production
- Page dynamique unique qui affiche automatiquement les données du logement courant
- Navigation structurée autour de cinq menus : Mon Séjour, Le Logement, Découvrir la Ville, Services Liberty, Assistant IA Liberty
- Pages/modules intégrés : Accueil, Arrivée, Départ, Wi-Fi & Équipements, Guide du Logement, Assistance, Bons Plans Liberty, Réservation d'Activités, City Guide Liberty, Transport, Services supplémentaires, Départ tardif, Réservation Directe Liberty, Programme Fidélité, Mon Séjour, Assistant IA Liberty, Centre de Services Liberty
- Panneau d'administration pour créer et modifier les logements sans toucher au code
- Centre de Services Liberty pour demandes voyageurs sans WhatsApp
- Assistant IA connecté aux données du logement
- Limites IA par session et par jour pour maîtriser les coûts
- QR code Wi-Fi local, sans service externe
- Boutons itinéraires Google Maps / Apple Plans
- Formulaire CRM avec consentement marketing
- Pages Mentions légales et Confidentialité / RGPD
- Bandeau cookies pour les cookies strictement nécessaires
- Pages publiques `/logement/{slug}` et `/guide/{ville}` prêtes pour réservation directe et SEO city guides
- Emplacements prêts pour les modules futurs : services payants, réservation directe, espace propriétaire, statistiques

## Assistant IA Liberty

Chaque logement possède dans la base :

- une clé API OpenAI dédiée
- un modèle OpenAI
- des instructions Assistant IA propres au logement
- les données opérationnelles utilisées comme contexte

Sans clé API réelle, l'application utilise un moteur local de secours connecté aux données du logement pour les réponses essentielles : Wi-Fi, parking, boîte à clés, adresse, départ.

Avec clé API renseignée depuis l'administration, l'appel est fait côté serveur vers l'API OpenAI Responses. La clé n'est jamais envoyée au navigateur.

## Configuration avant production

Créer un fichier `.env` à partir de `.env.example` :

```text
PORT=4173
BASE_URL=https://liberty.fr
SESSION_SECRET=une-longue-valeur-secrete
ADMIN_PASSWORD=mot-de-passe-admin-fort
FORCE_HTTPS=true
OPENAI_MODEL=gpt-5.5
```

À faire avant GitHub et cPanel :

- remplacer tous les mots de passe de test
- renseigner les vraies données logements
- ajouter les vraies instructions IA fournies par Liberty
- renseigner les clés OpenAI par logement
- valider la stratégie d'hébergement cPanel Node.js
- configurer MySQL avec `DATABASE_URL`
- activer HTTPS et cookies sécurisés en production
- compléter les informations société/hébergeur dans les pages légales
- vérifier les textes RGPD avec le conseil juridique de Liberty

## Arrêt demandé

Le projet est volontairement arrêté avant :

- déploiement cPanel
- création ou push GitHub
- mise en production publique

## Structure

```text
server.js              Serveur, routes, base, administration, API assistant
database.js            Couche DB SQLite local / MySQL production
public/styles.css      Identité graphique Liberty
public/traveler.js     Chat, demandes services, interactions voyageurs
assets/liberty-hero.png
data/liberty.sqlite    Base locale générée automatiquement
docs/database-production.md
docs/migrations/
```

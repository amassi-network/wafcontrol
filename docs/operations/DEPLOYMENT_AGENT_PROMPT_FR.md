# Prompt de déploiement WAFControl pour un nouveau site

Copier le bloc ci-dessous dans une nouvelle session d’agent. Remplacer uniquement
les valeurs entre crochets qui sont déjà connues. L’agent doit demander les
valeurs réellement bloquantes qui restent absentes et ne doit jamais reprendre
automatiquement les adresses, exclusions ou secrets d’Ironitia.

---

Tu es un ingénieur Linux, Nginx, ModSecurity, OWASP CRS, Django, PostgreSQL,
WebAuthn et sécurité opérationnelle. Tu dois préparer puis, si l’autorisation
de mutation est bien présente, déployer notre fork WAFControl sur une nouvelle
machine pour un autre site.

## Objectif

Reproduire l’architecture WAFControl validée par Ironitia, en l’adaptant au
nouveau site sans copier ses secrets, ses exclusions applicatives, ses
certificats, ses données ou ses adresses IP.

Le résultat doit comprendre :

- Nginx avec ModSecurity v3 et OWASP CRS ;
- WAFControl depuis notre fork ;
- PostgreSQL, Redis, Gunicorn et Celery ;
- tableau d’administration HTTPS à accès restreint ;
- observation ModSecurity en `DetectionOnly` pendant 7 à 14 jours ;
- exclusions gérées dans l’ordre BEFORE → CRS → AFTER ;
- alertes au fil de l’eau vers MapAttack par RFC3164/TCP ;
- sauvegardes base, code et configurations ;
- prise en charge TOTP et YubiKey/WebAuthn ;
- tests, preuves, documentation et rollback.

## Paramètres du nouveau site

Utilise les valeurs suivantes. Une valeur `[TO BE COMPLETED]` ne doit jamais
être devinée.

```text
TARGET_HOST=[TO BE COMPLETED]
SSH_USER=[TO BE COMPLETED]
SITE_NAME=[TO BE COMPLETED]
WAF_DOMAIN=[TO BE COMPLETED]
WAF_PUBLIC_IP=[TO BE COMPLETED]
WAF_ADMIN_ALLOW_IP=[TO BE COMPLETED]
WAF_ADMIN_PORT=7000
WAF_CERT_NAME=[TO BE COMPLETED]
WAF_CRS_VERSION=4.29.0
WAF_MAPATTACK_HOST=[TO BE COMPLETED]
WAF_MAPATTACK_PORT=514
WAF_APP_ROOT=/opt/WafControl
WAF_SERVICE_USER=root
WAF_SERVICE_GROUP=www-data
PROTECTED_NGINX_VHOSTS=[TO BE COMPLETED]
BACKUP_DESTINATION=[TO BE COMPLETED]
OBSERVATION_OWNER=[TO BE COMPLETED]
OBSERVATION_END_DATE=[TO BE COMPLETED]
```

Dépôt obligatoire :

```text
REPOSITORY=git@github.com:amassi-network/wafcontrol.git
BRANCH=agent/managed-exclusions-address-lists
REFERENCE_VALIDATED_COMMIT=17661c8
DEPLOY_COMMIT=[TO BE COMPLETED]
```

Ne déploie jamais implicitement la tête de branche. Si `DEPLOY_COMMIT` est
vide, propose le commit validé ci-dessus ou un commit plus récent explicitement
revu, puis enregistre le hash complet retenu.

## Phase 1 — Retrouver le dépôt et les instructions

1. Commence par afficher le répertoire de travail et rechercher le dépôt local
   sans parcourir inutilement tout le système :
   - utilise `pwd`, `rg --files`, `git remote -v` et `git status` ;
   - cherche d’abord un répertoire `wafcontrol-fork` dans l’espace de travail
     fourni ;
   - le chemin de référence historique est
     `/home/xave/W3TEL Dropbox/Xavier Lemaire/www_ironitia_com/wafcontrol-fork`,
     mais ne suppose pas qu’il existe sur un autre poste.
2. Vérifie que le remote correspond à
   `amassi-network/wafcontrol.git`, et non au dépôt upstream OWASP.
3. Si aucun clone n’existe, clone notre fork dans un nouveau répertoire propre.
4. Place-toi sur le commit exact retenu, en mode détaché ou sur une branche de
   déploiement dédiée.
5. Vérifie que le dépôt local est propre avant toute modification.
6. Lis intégralement, dans cet ordre :
   - `README.md` ;
   - `docs/operations/DEPLOYMENT.md` ;
   - `docs/operations/AGENT_HANDOFF.md` ;
   - `docs/operations/WEBAUTHN_YUBIKEY.md` ;
   - `docs/operations/PRODUCTION_INVENTORY_IRONITIA.md`.
7. L’inventaire Ironitia est uniquement une référence technique. N’en copie
   aucune valeur propre au site sauf si elle apparaît explicitement dans les
   paramètres du nouveau site.

Si un document ou un script référencé manque au commit retenu, arrête-toi et
signale précisément le fichier absent.

## Phase 2 — Audit en lecture seule

Avant toute mutation :

1. Identifie l’OS, les versions, les dépôts APT et les mises à jour en attente.
2. Inventorie Nginx/Apache, les modules dynamiques, ModSecurity, CRS, les
   virtual hosts, certificats, ports, firewall et éventuel gestionnaire de
   configuration.
3. Inventorie PostgreSQL, Redis, rsyslog, systemd, sauvegardes et espace disque.
4. Vérifie DNS, routage, NAT et accès aux ports 80/443/7000.
5. Vérifie la connectivité TCP sortante vers MapAttack.
6. Identifie le propriétaire de chaque vhost protégé, les health checks et les
   applications derrière Nginx.
7. Recherche tout WAF ou automatisme existant susceptible d’entrer en conflit.
8. Ne lis et n’affiche aucun secret. Tu peux vérifier présence, permissions et
   validité sans afficher la valeur.
9. Produis un rapport préflight avec :
   - état compatible ou bloquant ;
   - différences par rapport au baseline documenté ;
   - sauvegarde/snapshot nécessaire ;
   - fichiers qui seront modifiés ;
   - commandes de validation ;
   - rollback exact.

Ne commence pas le déploiement si la demande ne t’autorise que l’audit ou la
préparation.

## Phase 3 — Conditions d’arrêt obligatoires

Arrête-toi avant mutation si :

- la cible SSH, le domaine, le commit ou les vhosts sont ambigus ;
- aucun snapshot ou rollback récupérable n’est disponible ;
- un autre outil gère les mêmes fichiers Nginx/ModSecurity ;
- le port 7000 ne peut pas être limité à l’adresse autorisée ;
- le certificat ou le DNS ne correspond pas au RP ID WebAuthn ;
- la destination MapAttack ou son protocole n’est pas confirmé ;
- une commande de test, migration ou sauvegarde échoue ;
- un secret apparaît dans Git, un log ou une commande ;
- une exclusion Ironitia est sur le point d’être copiée ;
- l’ordre BEFORE → CRS → AFTER n’est pas garanti.

## Phase 4 — Rendu de la configuration

Utilise exclusivement le générateur versionné :

```bash
cd <CHEMIN_DU_DEPOT>
sudo env \
  WAF_DOMAIN="$WAF_DOMAIN" \
  WAF_PUBLIC_IP="$WAF_PUBLIC_IP" \
  WAF_ADMIN_ALLOW_IP="$WAF_ADMIN_ALLOW_IP" \
  WAF_ADMIN_PORT="$WAF_ADMIN_PORT" \
  WAF_CERT_NAME="$WAF_CERT_NAME" \
  WAF_CRS_VERSION="$WAF_CRS_VERSION" \
  WAF_MAPATTACK_HOST="$WAF_MAPATTACK_HOST" \
  WAF_MAPATTACK_PORT="$WAF_MAPATTACK_PORT" \
  WAF_APP_ROOT="$WAF_APP_ROOT" \
  WAF_SERVICE_USER="$WAF_SERVICE_USER" \
  WAF_SERVICE_GROUP="$WAF_SERVICE_GROUP" \
  ./scripts/render_deployment_config.sh /root/wafcontrol-rendered
```

Contrôle ensuite :

- aucune marque `@@...@@` non résolue ;
- aucun secret dans les fichiers rendus ;
- `wafcontrol.env` en mode 0600 ;
- IP, domaine, port, certificat et destination syslog corrects ;
- WebAuthn :
  - `WEBAUTHN_RP_ID` contient uniquement le nom DNS, sans schéma ni port ;
  - `WEBAUTHN_ALLOWED_ORIGINS` contient l’origine HTTPS exacte avec le port ;
  - aucun wildcard ;
- ordre ModSecurity :
  1. configuration de base ;
  2. exclusions propres au nouveau site ;
  3. WAFControl BEFORE ;
  4. CRS setup ;
  5. CRS rules ;
  6. WAFControl AFTER.

Présente le diff rendu avant installation.

## Phase 5 — Déploiement

Suis exactement `docs/operations/DEPLOYMENT.md`, sans réinventer une autre
procédure.

Points non négociables :

1. Snapshot et sauvegarde vérifiée avant changement.
2. Clone ou archive du commit exact.
3. Dépendances installées depuis `requirements.txt`.
4. Secrets uniques générés sur la cible, jamais copiés d’Ironitia.
5. PostgreSQL avec compte dédié et sans privilège `CREATEDB` en production.
6. `manage.py migrate --plan` avant `manage.py migrate`.
7. `manage.py check`, tests et collecte statique.
8. ModSecurity commence en `DetectionOnly`.
9. Exclusions applicatives vides ou explicitement validées pour ce site.
10. `nginx -t` obligatoire avant chaque reload.
11. Port 7000 protégé dans Nginx et, si possible, dans le firewall amont/hôte.
12. Rsyslog TCP avec file disque et retry illimité vers MapAttack.
13. Timer de sauvegarde installé, lancé une première fois et checksums vérifiés.
14. Services redémarrés seulement après validation du candidat.
15. Révision exacte écrite dans `$WAF_APP_ROOT/.deployed-revision`.

Prépare un rollback automatique pour restaurer code et environnement si la
migration applicative, le redémarrage ou le health check échoue. Une migration
additive peut rester en base si l’ancien code l’ignore, mais documente-le.

## Phase 6 — Tests d’acceptation

Exécute et conserve les preuves suivantes :

- suite complète Django sans échec ;
- migrations toutes appliquées ;
- `nginx -t` réussi ;
- services actifs :
  - nginx ;
  - postgresql ;
  - redis-server ;
  - rsyslog ;
  - wafcontrol ;
  - wafcontrol-celery-worker ;
  - wafcontrol-celery-beat ;
  - wafcontrol-backup.timer ;
- site protégé disponible en HTTPS ;
- tableau WAF accessible depuis l’IP autorisée ;
- port 7000 refusé depuis une source externe non autorisée ;
- assets du tableau chargés ;
- événement ModSecurity de test stocké avec IP/ports source et destination ;
- événement reçu et correctement parsé par MapAttack ;
- aucune duplication lors de la relecture d’une transaction ;
- ordre BEFORE → CRS → AFTER ;
- sauvegardes base/code/configuration et checksums valides ;
- login TOTP inchangé ;
- onglet YubiKey présent ;
- enrôlement et login mot de passe + clé testés avec une vraie clé ou
  l’authenticator CTAP2 virtuel de Chrome ;
- CSRF sans token refusé ;
- RP ID et origine WebAuthn exacts.

Utilise uniquement des adresses TEST-NET pour générer de faux événements.

## Phase 7 — Observation

Planifie 7 à 14 jours en `DetectionOnly`.

Pour chaque exclusion proposée, exige :

- application ;
- règle et variable précises ;
- chemin/méthode/hôte les plus étroits possibles ;
- preuve du faux positif ;
- justification ;
- propriétaire ;
- approbateur ;
- date de révision ou expiration.

N’active pas automatiquement `SecRuleEngine On`. Cette décision nécessite les
résultats d’observation, le rollback et l’accord du propriétaire applicatif.

## Compte rendu final obligatoire

Rends un rapport contenant :

- chemin local du dépôt utilisé ;
- remote Git ;
- branche et commit complet ;
- cible, domaine et date ;
- versions OS/Nginx/ModSecurity/CRS/Python/Django/fido2/PostgreSQL/Redis ;
- fichiers et unités installés ;
- migrations appliquées ;
- configuration WebAuthn sans secret ;
- résultat de chaque test d’acceptation ;
- preuve de restriction du port 7000 ;
- preuve de réception MapAttack ;
- sauvegarde, checksums et prochaine exécution du timer ;
- date de fin d’observation ;
- écarts et dettes techniques ;
- point de rollback exact ;
- informations restant à fournir.

Ne retourne jamais mot de passe, clé privée, cookie, challenge WebAuthn,
contenu de `.env`, dump PostgreSQL ou donnée client.

---

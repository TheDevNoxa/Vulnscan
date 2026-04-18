# 🕷️ web-vulnscan

Scanner de vulnérabilités web basique écrit en Python — projet éducatif réalisé dans le cadre du Bac Pro CIEL.

## Checks effectués

| Catégorie | Description |
|---|---|
| **En-têtes HTTP** | Détecte les headers de sécurité manquants (CSP, HSTS, X-Frame-Options…) |
| **SQL Injection** | Teste les paramètres GET avec des payloads courants, détecte les erreurs SQL |
| **XSS** | Détecte si un paramètre reflète du contenu sans échappement |
| **Fichiers sensibles** | Teste l'accès à `.env`, `.git`, `phpinfo.php`, backups… |
| **Directory listing** | Vérifie si le listage de répertoires est activé |

## Installation

```bash
git clone https://github.com/thedevnoxa/web-vulnscan
cd web-vulnscan
pip install -r requirements.txt
```

**requirements.txt**
```
requests>=2.31.0
```

## Utilisation

```bash
# Scan complet
python3 vulnscan.py -u https://example.com/page?id=1

# Sans les checks SQLi
python3 vulnscan.py -u https://example.com --no-sqli

# Juste les headers
python3 vulnscan.py -u https://example.com --no-sqli --no-xss --no-files
```

## Exemple de sortie

```
[*] Starting scan on: http://testphp.vulnweb.com/listproducts.php?cat=1

[*] Checking security headers ...
[*] Testing SQL injection ...
[*] Testing XSS reflection ...
[*] Checking sensitive files ...

=================================================================
  SCAN RESULTS — http://testphp.vulnweb.com/listproducts.php?cat=1
=================================================================
  [CRITICAL ] SQL Injection            Param 'cat' — error pattern 'warning: mysql' detected
  [HIGH     ] Sensitive File           /.git/HEAD accessible (HTTP 200, 24 bytes)
  [MEDIUM   ] Missing Header           Content-Security-Policy not set
  [MEDIUM   ] Missing Header           Strict-Transport-Security not set
  [LOW      ] Missing Header           Referrer-Policy not set
```

## ⚠️ Avertissement légal

Cet outil est destiné à un usage **éducatif uniquement**.  
Testez uniquement des applications dont vous êtes propriétaire ou pour lesquelles vous avez une autorisation écrite.  
Des cibles légales pour s'entraîner : [DVWA](https://dvwa.co.uk/), [HackTheBox](https://hackthebox.com), [TryHackMe](https://tryhackme.com).

## Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)

---
*Projet réalisé par [Noxa](https://github.com/thedevnoxa) — Bac Pro CIEL*

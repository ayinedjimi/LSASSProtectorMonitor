# 🚀 LSASSProtectorMonitor


**Ayi NEDJIMI Consultants - WinToolsSuite**

## Vue d'ensemble

LSASSProtectorMonitor est un outil de surveillance et de détection des tentatives d'accès suspects au processus LSASS (Local Security Authority Subsystem Service), une cible privilégiée des attaquants pour l'extraction de credentials en mémoire.


## Importance de la protection LSASS

Le processus `lsass.exe` stocke en mémoire :
- Hashes de mots de passe (NTLM)
- Tickets Kerberos (TGT)
- Credentials en clair (dans certaines configurations)
- Secrets LSA

Les attaquants utilisent des outils comme **Mimikatz**, **ProcDump**, ou **Comsvcs.dll** pour dumper la mémoire de LSASS et extraire ces secrets.


## ✨ Fonctionnalités principales

### 1. Détection de processus suspects
Surveillance continue (toutes les 5 secondes) pour détecter les processus dont le nom correspond à des patterns d'outils de dumping connus :
- `mimikatz.exe`
- `procdump.exe` / `procdump64.exe`
- `dumpert.exe`
- `nanodump.exe`
- `sqldumper.exe`
- `rdrleakdiag.exe`
- `comsvcs.dll` (utilisé via rundll32)
- `taskmgr.exe` (peut dumper LSASS)

### 2. Monitoring non-intrusif
- **Pas de lecture mémoire** : L'outil n'utilise PAS `PROCESS_VM_READ` pour éviter de déclencher des alertes
- **Accès limité** : Utilise `PROCESS_QUERY_LIMITED_INFORMATION` pour identifier les processus
- **Approche safe** : Pas de dumping réel, uniquement de la détection

### 3. Intégration Sysmon
Si Sysmon est installé, l'outil analyse les événements :
- **Event ID 8** : CreateRemoteThread
- Détection de threads distants créés dans le processus LSASS
- Identification du processus source

### 4. Informations collectées
Pour chaque activité suspecte détectée :
- **Horodatage** : Date et heure précises
- **Processus suspect** : Nom et chemin complet
- **PID** : Identifiant du processus
- **Type d'accès** : Nature de l'activité détectée
- **Utilisateur** : Compte sous lequel s'exécute le processus
- **Niveau d'alerte** : Description de la menace

### 5. Export des alertes
- Export CSV UTF-8 avec BOM pour Excel
- Format : Horodatage;Processus;PID;Type;Utilisateur;Alertes


## Techniques de détection

### Détection par nom de processus
```cpp
Patterns suspects :
- mimikatz (toutes variantes)
- procdump (ProcDump de Sysinternals)
- dumpert (outil de dumping LSASS)
- nanodump (dumper léger)
- sqldumper (SQL Server, utilisé pour LSASS)
- rdrleakdiag (RD Leak Diagnostics)
- comsvcs (via rundll32 MiniDump)
- taskmgr (Task Manager, peut créer des dumps)
```

### Détection via Sysmon
```xml
Event ID 8: CreateRemoteThread
TargetImage: C:\Windows\System32\lsass.exe
SourceImage: <Processus attaquant>
SourceProcessId: <PID>
```


# 🚀 Télécharger Sysmon depuis Sysinternals

# 🚀 Installer avec configuration standard

## Architecture technique

### Composants
1. **Interface graphique** : Win32 native avec ListView temps réel
2. **Thread de monitoring** : std::thread pour la surveillance continue
3. **Énumération processus** : CreateToolhelp32Snapshot + Process32First/Next
4. **Analyse Event Log** : Windows Event Log API (wevtapi.lib)
5. **RAII** : AutoHandle pour la gestion des handles
6. **Threading safe** : std::mutex + std::atomic pour synchronisation

### Flux de fonctionnement
```
1. Démarrage monitoring
   ↓
2. Trouver PID de lsass.exe
   ↓
3. Boucle toutes les 5 secondes:
   a. Énumérer tous les processus
   b. Vérifier noms suspects
   c. Pour chaque suspect:
      - Ouvrir avec QUERY_LIMITED_INFORMATION
      - Extraire chemin complet
      - Identifier utilisateur
      - Générer alerte
   ↓
4. Vérification Sysmon Event Log
   a. Query Event ID 8 (CreateRemoteThread)
   b. Filtrer sur TargetImage = lsass.exe
   c. Extraire processus source
   d. Générer alerte CRITIQUE
```


## Compilation

### Prérequis
- Visual Studio 2017 ou plus récent avec les outils C++
- Windows SDK

### Compilation automatique
```batch
go.bat
```

Le script :
1. Détecte automatiquement Visual Studio
2. Configure l'environnement de compilation
3. Compile avec les optimisations
4. Propose de lancer l'exécutable

### Compilation manuelle
```batch
cl.exe /EHsc /O2 /W3 /std:c++17 /D UNICODE /D _UNICODE LSASSProtectorMonitor.cpp /link psapi.lib wevtapi.lib comctl32.lib /OUT:LSASSProtectorMonitor.exe
```


## 🚀 Utilisation

### Interface graphique
1. **Démarrer Monitoring** : Lance la surveillance continue de LSASS
2. **Arrêter** : Stoppe le monitoring
3. **Exporter Alertes** : Sauvegarde toutes les alertes au format CSV

### Privilèges requis
- **Utilisateur standard** : Suffisant pour la détection basique
- **Administrateur** : Recommandé pour accéder à plus d'informations processus et Event Log

### Installation Sysmon (optionnel mais recommandé)
```powershell
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "Sysmon64.exe"

.\Sysmon64.exe -accepteula -i
```

Configuration Sysmon pour LSASS :
```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <CreateRemoteThread onmatch="include">
      <TargetImage condition="contains">lsass.exe</TargetImage>
    </CreateRemoteThread>
  </EventFiltering>
</Sysmon>
```


## Logging

Tous les événements sont enregistrés dans :
```
%TEMP%\WinTools_LSASSProtectorMonitor_log.txt
```

Format des logs :
```
2025-10-20 14:30:45 | === LSASSProtectorMonitor démarré ===
2025-10-20 14:30:46 | Début monitoring LSASS (PID: 732)
2025-10-20 14:31:02 | ALERTE: mimikatz.exe (PID 4528) - ATTENTION: Outil de dumping potentiel
2025-10-20 14:31:15 | Vérification événements Sysmon pour CreateRemoteThread sur LSASS
2025-10-20 14:31:16 | ALERTE: procdump64.exe (PID 5632) - CRITIQUE: Thread distant créé dans LSASS
2025-10-20 14:32:00 | Arrêt monitoring LSASS
```


# 🚀 Activer Credential Guard via GPO

# 🚀 Activer RunAsPPL

# 🚀 Bloquer vol de credentials depuis LSASS

## Indicateurs de compromission

### Alertes critiques
1. **Mimikatz détecté**
   - Outil d'extraction de credentials le plus répandu
   - Action recommandée : Bloquer immédiatement, analyser le système

2. **ProcDump sur LSASS**
   - Outil légitime Sysinternals utilisé pour dumping LSASS
   - Action recommandée : Vérifier si usage autorisé par IT

3. **CreateRemoteThread vers LSASS**
   - Technique d'injection de code
   - Action recommandée : Investigation approfondie, possible malware

4. **Comsvcs.dll + rundll32**
   - Technique de dumping LSASS via DLL native Windows
   - Commande type : `rundll32.exe comsvcs.dll, MiniDump <PID> dump.dmp full`
   - Action recommandée : Bloquer, analyser dump créé

### Faux positifs potentiels
- **Task Manager (taskmgr.exe)** : Administrateurs peuvent créer des dumps légitimes
- **SQLDumper.exe** : Peut être utilisé légitimement par DBA, mais suspect sur workstation
- **Outils de monitoring** : Solutions EDR peuvent accéder à LSASS


## 🚀 Cas d'usage

### 1. Détection d'attaque Pass-the-Hash
Un attaquant tente d'extraire les hashes NTLM de LSASS pour réutilisation.

**Scénario** :
```
1. Attaquant lance mimikatz.exe
2. LSASSProtectorMonitor détecte le processus
3. Alerte générée avec PID et utilisateur
4. Administrateur peut tuer le processus avant extraction
```

### 2. Détection de compromission post-exploitation
Après un accès initial, l'attaquant tente d'élever ses privilèges.

**Scénario** :
```
1. Malware télécharge procdump64.exe
2. Exécution : procdump64.exe -ma lsass.exe lsass.dmp
3. Détection immédiate par l'outil
4. Intervention avant exfiltration du dump
```

### 3. Monitoring proactif
Surveillance continue des environnements sensibles (Domain Controllers, serveurs critiques).

**Scénario** :
```
1. Monitoring 24/7 activé
2. Toute activité suspecte remontée en temps réel
3. Export régulier des alertes pour analyse SIEM
4. Baseline de sécurité établie
```


## Défenses complémentaires

### 1. Credential Guard
Activer Windows Credential Guard pour isoler LSASS :
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1
```

### 2. RunAsPPL (Protected Process Light)
Protéger LSASS contre les accès mémoire :
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
```

### 3. Attack Surface Reduction (ASR)
Règles ASR pour bloquer le dumping LSASS :
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
```

### 4. Audit de sécurité
Activer l'audit des accès aux objets :
```
Configuration > Stratégies Windows > Paramètres de sécurité > Stratégies d'audit avancées
> Accès aux objets > Auditer le handle du noyau
```


## Limitations

1. **Détection par signature** : Basé sur des noms de processus connus, un attaquant peut renommer les outils
2. **Pas de blocking** : L'outil détecte mais ne bloque pas automatiquement
3. **Sysmon optionnel** : La détection de CreateRemoteThread nécessite Sysmon
4. **Techniques avancées** : Ne détecte pas les techniques sans processus (in-memory, reflective DLL injection)
5. **Performance** : Vérification toutes les 5 secondes (compromis détection/performance)


## Techniques d'évasion (à connaître)

Les attaquants peuvent :
1. **Renommer les outils** : mimikatz.exe → svchost.exe
2. **Injection in-memory** : Pas de fichier sur disque
3. **LSASS Shtinkering** : Techniques pour éviter les détections
4. **Process Hollowing** : Injection dans un processus légitime
5. **Direct System Calls** : Bypass des hooks EDR


## Recommandations

### Pour les administrateurs
1. **Monitoring continu** : Déployer sur les serveurs critiques
2. **Corrélation SIEM** : Intégrer les exports CSV dans un SIEM
3. **Formation** : Sensibiliser les équipes aux alertes
4. **Réponse incident** : Procédure définie pour chaque type d'alerte

### Pour les analystes SOC
1. **Baseline** : Établir une référence des processus légitimes
2. **Investigation** : Chaque alerte doit être analysée
3. **Threat hunting** : Rechercher des IOCs complémentaires
4. **Enrichissement** : Croiser avec d'autres sources (EDR, firewall, proxy)


## Améliorations futures

- [ ] Détection de comportements anormaux (ML/heuristiques)
- [ ] Intégration API Windows Defender ATP
- [ ] Support détection PPLDump et similaires
- [ ] Alertes temps réel (email, webhook)
- [ ] Blocking automatique (optionnel)
- [ ] Analyse mémoire pour détection in-memory
- [ ] Support signatures YARA pour détection avancée


## Références

- [Mimikatz - GitHub](https://github.com/gentilkiwi/mimikatz)
- [Credential Dumping: LSASS - MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Windows Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
- [LSA Protection (RunAsPPL)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Sysmon - Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)


## Support

**Ayi NEDJIMI Consultants**
Pour toute question ou assistance technique.

- --

**Version** : 1.0
**Date** : 2025-10-20
**Licence** : Usage interne Ayi NEDJIMI Consultants


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>
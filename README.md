# 🔐 TPM2 TOTP Generator

Générateur de codes **TOTP (Time-Based One-Time Password)** écrit en **C**, utilisant un **TPM 2.0 (Trusted Platform Module)** pour protéger les opérations cryptographiques et les clés sensibles.

Le programme génère un OTP à **6 chiffres**, renouvelé toutes les **30 secondes**, à partir d'un HMAC-SHA256 calculé directement par le TPM.

Il intègre également plusieurs mécanismes de durcissement Linux : **seccomp**, `mlock()`, désactivation des core dumps et saisie sécurisée du mot de passe.

---

## ✨ Fonctionnalités

* 🔑 Génération de TOTP à 6 chiffres
* ⏱️ Fenêtre temporelle de 30 secondes
* 🛡️ Calcul HMAC-SHA256 effectué par le TPM
* 🔐 Clé TPM persistante protégée par mot de passe
* 💾 Utilisation de la mémoire NV du TPM pour maintenir un compteur
* 🧠 Protection des données sensibles avec `mlock()`
* 🧹 Effacement explicite des mots de passe en mémoire
* 🚫 Désactivation des core dumps
* 🔒 Filtrage des appels système avec `seccomp`
* ⌨️ Saisie du mot de passe sans écho terminal
* ✅ Vérification interactive de l'OTP généré

---

## 🏗️ Architecture

Le fonctionnement général est le suivant :

```text
Utilisateur
    │
    │ Mot de passe TPM
    ▼
┌─────────────────────┐
│   Application C     │
│                     │
│  - Termios          │
│  - mlock            │
│  - secure_clear     │
│  - seccomp          │
└──────────┬──────────┘
           │
           │ TSS2 / ESAPI
           ▼
┌─────────────────────┐
│       TPM 2.0       │
│                     │
│  Persistent Key     │
│        │            │
│        ├── HMAC     │
│        │   SHA-256  │
│        │            │
│        └── TOTP     │
│                     │
│  NV Counter         │
└─────────────────────┘
```

Le secret cryptographique utilisé pour le HMAC est associé à une clé TPM persistante.

L'application transmet au TPM la valeur temporelle :

```text
floor(timestamp / 30)
```

Le TPM calcule ensuite un **HMAC-SHA256**. Une troncature dynamique est appliquée au résultat afin d'obtenir un OTP à 6 chiffres.

---

## 🧰 Technologies utilisées

| Technologie        | Rôle                                               |
| ------------------ | -------------------------------------------------- |
| **C**              | Implémentation principale                          |
| **TPM 2.0**        | Protection des clés et opérations cryptographiques |
| **TSS2 / ESAPI**   | Communication avec le TPM                          |
| **HMAC-SHA256**    | Calcul cryptographique utilisé pour le TOTP        |
| **TPM NV Storage** | Stockage persistant du compteur                    |
| **seccomp**        | Restriction des appels système                     |
| **prctl**          | Durcissement du processus                          |
| **mlock**          | Empêche le swap des données sensibles              |
| **termios**        | Contrôle sécurisé de la saisie terminal            |
| **Linux TCTI**     | Communication avec `/dev/tpmrm0`                   |

---

## 🔐 Mesures de sécurité

### Protection du mot de passe

Le mot de passe TPM est lu directement depuis `/dev/tty`.

L'écho du terminal est temporairement désactivé :

```c
newt.c_lflag &= ~(ECHO | ISIG);
```

Le mot de passe n'est donc pas affiché pendant sa saisie.

---

### Protection contre le swap

Le buffer contenant le mot de passe est verrouillé en mémoire :

```c
mlock(password, sizeof(password));
```

Cela réduit le risque que son contenu soit écrit dans la zone de swap du système.

Lors du nettoyage :

```c
munlock(password, sizeof(password));
```

---

### Effacement sécurisé de la mémoire

Une fonction dédiée écrase explicitement les données sensibles :

```c
void secure_clear(void *buf, size_t len)
{
    if (!buf)
        return;

    volatile uint8_t *p = buf;

    while (len--)
        *p++ = 0;
}
```

Elle est notamment utilisée avant la fin du programme :

```c
secure_clear(password, sizeof(password));
```

---

### Désactivation des core dumps

Le programme empêche la génération de core dumps :

```c
prctl(PR_SET_DUMPABLE, 0);
```

Cela évite qu'un dump mémoire du processus expose accidentellement des informations sensibles.

---

### Sandbox seccomp

Un filtre **seccomp BPF** limite les appels système que le processus peut exécuter.

Le programme active également :

```c
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
```

puis applique son filtre :

```c
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
```

Tout appel système non autorisé peut alors provoquer l'arrêt du processus.

---

## 🔑 Gestion des clés TPM

### Handle de base

Les clés persistantes utilisent la base :

```c
#define TPM_KEY_BASE 0x81000000
```

Le handle de la clé est ensuite dérivé de l'UID Unix :

```c
uid_t uid = getuid();

TPM2_HANDLE k_idx =
    TPM_KEY_BASE + (uid * 997 % 0x1000);
```

Cela permet d'utiliser un emplacement de clé différent selon l'utilisateur.

---

### Création de la clé

Si aucune clé n'existe au handle calculé, le programme appelle :

```c
rotate_tpm_key(
    ctx,
    &tpm_key,
    k_idx,
    password,
    password_len
);
```

La clé créée est de type :

```c
TPM2_ALG_KEYEDHASH
```

avec un schéma :

```c
TPM2_ALG_HMAC
```

et l'algorithme :

```c
TPM2_ALG_SHA256
```

Elle est ensuite rendue persistante grâce à :

```c
Esys_EvictControl(...)
```

---

## ⏱️ Génération du TOTP

La génération commence par déterminer la fenêtre temporelle courante :

```c
uint64_t interval = htobe64(time(NULL) / 30);
```

Cette valeur est envoyée au TPM.

L'application demande ensuite au TPM de produire un HMAC :

```c
Esys_HMAC(
    ctx,
    key,
    ESYS_TR_PASSWORD,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    &buf,
    TPM2_ALG_SHA256,
    &hmac_out
);
```

Le résultat utilise ensuite une troncature dynamique :

```c
int offset =
    hmac_out->buffer[hmac_out->size - 1] & 0xf;

uint32_t bin_code;

memcpy(
    &bin_code,
    &hmac_out->buffer[offset],
    sizeof(bin_code)
);
```

Le code final est ramené sur six chiffres :

```c
*out_otp =
    (be32toh(bin_code) & 0x7fffffff) % 1000000;
```

Exemple :

```text
Your OTP: 482731
```

---

## 💾 Compteur NV

Le programme utilise un index TPM NV :

```c
#define NV_COUNTER_INDEX 0x01000001
```

Un espace de **8 octets** y est réservé.

Lors de son initialisation :

```c
TPM2B_NV_PUBLIC publicInfo = {
    .size = sizeof(TPMS_NV_PUBLIC),

    .nvPublic = {
        .nvIndex = nv_index,
        .nameAlg = TPM2_ALG_SHA256,

        .attributes =
            TPMA_NV_AUTHWRITE |
            TPMA_NV_AUTHREAD,

        .dataSize = 8
    }
};
```

Après chaque génération réussie d'un OTP, la valeur est lue :

```c
Esys_NV_Read(...)
```

puis incrémentée :

```c
uint64_t val = be64toh(count) + 1;
count = htobe64(val);
```

et réécrite dans le TPM :

```c
Esys_NV_Write(...)
```

> **Note :** dans l'implémentation présentée, ce compteur est maintenu parallèlement à la génération du TOTP. La valeur du compteur NV n'entre pas directement dans le calcul du code TOTP.

---

## 🔄 Déroulement du programme

Au lancement, l'application :

1. désactive les core dumps ;
2. ouvre `/dev/tty` ;
3. initialise la communication avec `/dev/tpmrm0` ;
4. initialise le contexte ESAPI ;
5. verrouille le buffer du mot de passe en mémoire ;
6. demande le mot de passe TPM ;
7. recherche la clé persistante associée à l'utilisateur ;
8. crée la clé si elle n'existe pas ;
9. initialise l'espace NV ;
10. active le filtre seccomp ;
11. génère le TOTP via le TPM ;
12. incrémente le compteur NV ;
13. affiche le code ;
14. demande à l'utilisateur de saisir le code pour le vérifier ;
15. nettoie les données sensibles et libère les ressources.

---

## 🖥️ Exemple d'utilisation

```text
Enter TPM Password:

Your OTP: 482731
Verify OTP: 482731

[SUCCESS] Access Granted.
```

En cas de mauvais code :

```text
Your OTP: 482731
Verify OTP: 123456

[FAILURE] Access Denied.
```

---

## 🧹 Nettoyage

Avant de quitter, l'application effectue notamment :

```c
secure_clear(password, sizeof(password));
munlock(password, sizeof(password));

if (tty_fd >= 0)
    close(tty_fd);

if (ctx)
    Esys_Finalize(&ctx);

if (tcti_ctx)
    Tss2_TctiLdr_Finalize(&tcti_ctx);
```

L'objectif est de limiter la durée de vie des données sensibles et de libérer correctement les ressources TPM.

---

## 📌 Constantes principales

```c
#define PASSWORD_MAX      64
#define NV_COUNTER_INDEX  0x01000001
#define TPM_KEY_BASE      0x81000000
```

| Constante          | Description                            |
| ------------------ | -------------------------------------- |
| `PASSWORD_MAX`     | Taille maximale du mot de passe        |
| `NV_COUNTER_INDEX` | Index NV utilisé pour le compteur      |
| `TPM_KEY_BASE`     | Base des handles des clés persistantes |

---

## ⚙️ Prérequis

Le programme cible un environnement **Linux** équipé d'un **TPM 2.0** accessible via :

```text
/dev/tpmrm0
```

Il dépend également de la pile logicielle **TPM2-TSS / TSS2**.

> Les commandes exactes d'installation des dépendances et de compilation ne figurent pas dans la documentation d'origine et doivent être adaptées à la distribution Linux et au système de build utilisés par le projet.

---

## ⚠️ Notes de sécurité

Ce projet manipule des primitives cryptographiques, des clés TPM et des mécanismes de sécurité bas niveau.

Avant une utilisation en production, il est recommandé de réaliser une revue spécifique portant notamment sur :

* les permissions TPM et NV ;
* la gestion des handles persistants ;
* la politique d'authentification TPM ;
* la liste exacte des syscalls autorisés par seccomp ;
* la gestion de toutes les valeurs de retour ;
* la restauration de l'état du terminal en cas d'erreur ;
* la concurrence entre plusieurs processus ;
* la gestion du cycle de vie des clés.

---

## 📚 Fonctions principales

| Fonction                     | Rôle                              |
| ---------------------------- | --------------------------------- |
| `secure_clear()`             | Efface un buffer sensible         |
| `read_password_secure()`     | Lit un mot de passe sans écho     |
| `setup_seccomp()`            | Active le sandbox seccomp         |
| `setup_nv_counter()`         | Initialise l'espace NV            |
| `increment_manual_counter()` | Incrémente le compteur persistant |
| `rotate_tpm_key()`           | Crée et persiste une clé TPM      |
| `generate_totp()`            | Génère un TOTP via HMAC-SHA256    |
| `main()`                     | Orchestre l'ensemble du programme |

---

## 🎯 Objectif du projet

Ce projet démontre comment combiner les fonctionnalités d'un **TPM 2.0** avec les mécanismes de sécurité disponibles sous Linux afin de construire un générateur d'OTP dont les opérations cryptographiques sensibles restent protégées par le TPM.

Il constitue notamment un exemple d'utilisation de :

```text
TPM 2.0
   +
TSS2 / ESAPI
   +
HMAC-SHA256
   +
Linux hardening
   =
TOTP protégé par matériel
```

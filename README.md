# Zed CLI

Prototype de déchiffrement et d'extraction d'archives `.zed` protégées par mot de passe. L'archive est lue sans être modifiée ; les fichiers déjà présents ne sont pas écrasés.

## Utilisation

Python 3.10 ou plus récent est nécessaire. Le script utilise OpenSSL `libcrypto` du système sur macOS et Linux. Sur les systèmes où cette bibliothèque n'est pas disponible, installez le moteur AES Python :

```sh
python3 -m pip install cryptography
```

Listez le contenu ou extrayez les fichiers :

```sh
python3 zed.py archive.zed --list
python3 zed.py archive.zed -o dossier_de_sortie
```

Le mot de passe est demandé de manière interactive. Il n'est pas passé en argument de la commande.

## Portée

Le prototype prend en charge les utilisateurs `passworduser`, AES-CBC-STREAM et AES-CBC-CTS (CBC-CS3), PBKDF2-SHA-256 et la dérivation PKCS#12 SHA-1/SHA-256 décrite dans la [documentation du format Zed](https://www.beuc.net/zed/zed.md). Les utilisateurs `rsauser` déverrouillés par certificat ne sont pas pris en charge.

Les tests utilisent des vecteurs publics et ne contiennent ni archive privée ni mot de passe :

```sh
python3 -m unittest discover -s tests
```

Ce projet est un prototype indépendant, sans lien avec l'éditeur de Zed.

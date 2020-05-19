![JSON Web Token Cracker](./images/jwtcat_logo.png)

# jwtcat

[![Language](https://img.shields.io/badge/Lang-Python-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/)

## A CPU-based JSON Web Token (JWT) cracker and - to some extent - scanner

`jwtcat` is a `Python script` designed to detect and exploit well-known cryptographic flaws present in JSON Web Token (JWT). These vulnerabilities, if successfully exploited by an adversary could allow authentication bypass, information disclosure and could ultimately lead to the compromise of an entire information system.

More information about JWT vulnerabilities can be found at: <https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/>

---

## Features

- Test against the following vulnerabilitie(s):
  - [CVE-2018-1000531](https://nvd.nist.gov/vuln/detail/CVE-2015-2951): JWT signature bypass due to the use of `None` hashing algorithm (`alg=none`)
- Password cracking of JWT signed with the HS256 hashing algorithm via:
  - Brute-force attacks
  - Wordlist attacks

---

## Requirements

`jwtcat` is written in Python 3 (and therefore **requires a minimum of `Python 3.6`**) in addition to the following libraries:

- coloredlogs: <https://pypi.org/project/coloredlogs/>
- PyJWT: <https://pypi.org/project/PyJWT/>
- tqdm: <https://pypi.org/project/tqdm/>

---

## Installation

1. Clone/download the repository:

```bash
git clone https://github.com/AresS31/jwtcat
cd jwtcat
```

2. (Optional but recommended) Create and activate a new `Python` virtual environment:

   - Create the virtual environment: `python -m venv env`
   - Activate the newly created environment:
     - On POSIX: `source ./env/bin/activate`
     - On Windows: `./env/Scripts/Activate.ps1`

3. Install `jwtcat`'s dependencies:

```bash
python -m pip install -r requirements.txt
```

---

## Usage

To get a list of options and switches use:

```bash
python jwtcat.py -h
```

To get a list of options and switches for brute force attacks:

```bash
python jwtcat.py brute-force -h
```

To get a list of options and switches for wordlist attacks:

```bash
python jwtcat.py wordlist -h
```

To test a JWT against [CVE-2018-1000531](https://nvd.nist.gov/vuln/detail/CVE-2015-2951) and HS256 brute-force attacks:

```bash
python jwtcat.py vulnerable -h
```

---

## Sponsor ♥

If you use `jwtcat` a lot (especially if it's used commercially), please consider donating as a lot of **time** and **effort** went into building and maintaining this project.

Press the "Sponsor" button on the top of this page to see ways of donating/sponsoring to this project.

---

## Contributions

Your feedback and contributions will be **much** appreciated.

---

## Roadmap

- [ ] Add more attack vectors
- [ ] Implement support for the `-tF, --token-file` swicth
- [ ] Implement support for multithreading or multiprocessing
- [ ] Improve the code logic for:
  - [ ] `TQDM` integration with the `logger`
- [ ] Improve the script performances

---

## Changelog

### v1.1 - May 2020:

- Added support for brute-force attacks
- Added checks to see if jwt is signed with HS256
- Added checks to see if jwt is vulnerable to [CVE-2018-1000531](https://nvd.nist.gov/vuln/detail/CVE-2015-2951)
- Added potfile options
- Code refactoring
- Improved the standard output formatting
- Switched from `python-colorlog` to `coloredlogs`

---

## Licenses

Copyright (C) 2017 - 2020 Alexandre Teyar

See [LICENSE](../blob/master/LICENSE) file for details.

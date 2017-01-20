#!/usr/bin/env python3
#    Copyright (C) 2017 Alexandre Teyar

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
from datetime import datetime, timedelta
from colorama import Fore, Back, Style
import jwt
import os
import signal
import sys
import time

DEBUG = Fore.BLUE + "[DEBUG] "
ERROR = Fore.RED + "[ERROR] "
INFO = Fore.GREEN + "[INFO] "
PAYLOAD = Fore.CYAN + "[PAYLOAD] "
RESET = Style.RESET_ALL
RESULT = Style.BRIGHT + Fore.CYAN + "[RESULT] "
SUMMARY = Fore.YELLOW + "[SUMMARY] "
WARNING = Fore.YELLOW + "[WARNING] "

def parse_args():
    """ Parse and validate user's command line
    """
    parser = argparse.ArgumentParser(description = "JSON Web Token brute-forcer")

    parser.add_argument("-t", "--token", dest = "token", help = "JSON Web Token", required = True, type = str)
    parser.add_argument("-v", "--verbose", dest = "verbose", help = "enable verbose -- display every attempt", required = False, action = "store_true")
    # Set the UTF-8 encoding and ignore error mode to avoid issues with the wordlist
    parser.add_argument("-w", "--wordlist", dest = "wordlist", help = "wordlist containing the passwords -- one per line", required = True, type = argparse.FileType('r', encoding = 'UTF-8', errors = 'ignore'))
 
    return parser.parse_args()

def run(token, word, verbose):
    """ Check if [word] can decrypt [token]
    """
    try:
        payload = jwt.decode(token, word, algorithm = 'HS256')
        return True

    except jwt.exceptions.InvalidTokenError:
        if verbose:
            print(DEBUG + "InvalidTokenError: " + Style.BRIGHT + word + RESET)
        return False
    except jwt.exceptions.DecodeError:
        print(WARNING + "DecodingError: " + Style.BRIGHT + word + RESET)
        return False
    except Exception as ex:
        print(ERROR + "Exception: " + Style.BRIGHT + "{}".format(ex) + RESET)
        return False

def main():
    try:
        args = parse_args()

        token = args.token
        wordlist = args.wordlist
        verbose = args.verbose

        ## Variables summary
        print(SUMMARY + "JWT: " + Style.BRIGHT + "{}".format(token) + RESET)
        print(SUMMARY + "Wordlist: " + Style.BRIGHT + "{}".format(wordlist.name) + RESET)

        start_time = time.time()
        print("[*] starting {}".format(time.ctime()))
        
        print(INFO + "Starting brute-force attacks" + RESET)
        print(WARNING + "Pour yourself some coffee, this might take a while..." + RESET)
        for entry in wordlist:
            word = entry.rstrip()
            result = run(token, word, verbose)

            if result:
                print(RESULT + "Secret key: " + Style.BRIGHT + "{}".format(word) + RESET) 

                # Save the holy secret into a file in case sys.stdout is not responding
                with open("jwtpot.potfile", "a+") as file:
                    file.write("{0}:{1}".format(token, word))
                    print(RESULT + "Secret key saved to location: " + Style.BRIGHT + "{}".format(file.name) + RESET)

                break

        end_time = time.time()
        print("[*] finished {}".format(time.ctime()))

        elapsed_time = end_time - start_time
        print("[*] elapsed time: {} sec".format(elapsed_time))

    except KeyboardInterrupt:
        print(WARNING + "CTRL+C pressed, exiting..." + RESET)

        wordlist.close()

        end_time = time.time()
        print("[*] finished {}".format(time.ctime()))

        elapsed_time = end_time - start_time
        print("[*] elapsed time: {} sec".format(elapsed_time))

if __name__ == "__main__":
    main()
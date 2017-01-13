#!/usr/bin/env python3
#title           :jwtcat.py
#description     :This will bruteforce a JWT secret key.
#author          :Alexandre Teyar
#date            :2017-01-11
#version         :0.1
#usage           :python jwtcat.py [-h] -t TOKEN [-v] -w WORDLIST
#notes           :
#python_version  :3.6
#================================================================

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
WARNING = Fore.YELLOW + "[WARNING] "

def parse_args():
    """ Parse and validate user's command line
    """
    parser = argparse.ArgumentParser(description = "JSON Web Token brute-forcer")

    parser.add_argument("-t", "--token", dest = "token", help = "JSON Web Token", required = True, type = str)
    parser.add_argument("-v", "--verbose", dest = "verbose", help = "enable verbose mode", required = False, action = "store_true")
    # Set the UTF-8 encoding and ignore error mode to avoid issues with the wordlist
    parser.add_argument("-w", "--wordlist", dest = "wordlist", help = "wordlist containing the secrets to try", required = True, type = argparse.FileType('r', encoding = 'UTF-8', errors = 'ignore'))
 
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
            print(INFO + "JWT: " + Style.BRIGHT + "{}".format(token) + RESET)
            print(INFO + "Wordlist: " + Style.BRIGHT + "{}".format(wordlist.name) + RESET)

            start_time = time.time()
            print("[*] starting {}".format(time.ctime()))
            
            print(INFO + "Starting brute-force attacks" + RESET)
            print(WARNING + "Pour yourself some coffee, this might take a while..." + RESET)
            for entry in wordlist:
                word = entry.rstrip()
                result = run(token, word, verbose)

                if result:
                    print(RESULT + "Secret key: " + Style.BRIGHT + word + RESET) 

                    # Save the holy secret into a file in case sys.stdout is not responding
                    with open("jwtpot.pot", "a+") as file:
                        file.write("{0}:{1}".format(token, word))
                        print(RESULT + "Secret key saved to location: " + Style.BRIGHT + "{}".format(file.name) + RESET)

                    break

            end_time = time.time()
            print("[*] finished {}".format(time.ctime()))

            elapsed_time = end_time - start_time
            print("[*] elapsed time: {} sec".format(elapsed_time))

        except KeyboardInterrupt:
            print(WARNING + "Signal caught, exiting gracefully..." + RESET)

            wordlist.close()

            end_time = time.time()
            print("[*] finished {}".format(time.ctime()))

            elapsed_time = end_time - start_time
            print("[*] elapsed time: {} sec".format(elapsed_time))

            sys.exit(0)

if __name__ == "__main__":
    main()
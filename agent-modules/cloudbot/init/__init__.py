"""
module: cloudbot.init
  1, initialize machine parameters, check and register machine in ldap
  2, list ethernet/wireless ip addresses and register in ldap
"""

__all__ = ["preInit","postInit"]

from helpClass import *


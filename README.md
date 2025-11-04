# Enlogic-PDU-CLI
Enlogic PDU CLI commands  to turn on, off, reboot, etc... ports, multiple ports at a time or multiple pdu via a list of ips/hosts, works with a config file to store user/password other other info. 


usage: enlogic_cli.py [-h] [-c CONFIG] [-H HOST] [-u USER] [-P PASSWORD] [-k] [--secure] [-x]
                      [--https] [-d PDUID] [--low-bank-max LOW_BANK_MAX] [--debug] [--config-help]
                      [{hosts,setup,list,get,on,off,reboot,on_delay,off_delay,reboot_delay,multi}]

Enlogic PDU CLI. Globals first, then action. Example:
  enlogic.py --user u --password p --insecure --host 10.0.0.1 get --port 8

positional arguments:
  {hosts,setup,list,get,on,off,reboot,on_delay,off_delay,reboot_delay,multi}
                        Command to run (appears after globals)

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Config file (default: /home/awatkins/.enlogic.ini if present)
  -H HOST, --host HOST  Nickname or IP (nickname resolved via [hosts])
  -u USER, --user USER  Username (defaults to [auth] user)
  -P PASSWORD, --password PASSWORD
                        Password (defaults to [auth] password)
  -k, --insecure        Skip TLS verification
  --secure              Verify TLS
  -x, --http            Use HTTP instead of HTTPS
  --https               Use HTTPS
  -d PDUID, --pduid PDUID
                        PDU ID (override)
  --low-bank-max LOW_BANK_MAX
                        Outlet1 bank size (default 24)
  --debug               Print HTTP request/exception debug to stderr
  --config-help         Show config file help and exit

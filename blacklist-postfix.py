#!/usr/bin/python3

import os, sys, stat, regex, socket

################################################################################################################################################################
###   sanity checks   ##########################################################################################################################################
################################################################################################################################################################

if sys.stdin.isatty():	# This script expects input from pipe. Exit otherwise.
    print('sys.stdin is not a pipe')
    sys.exit(1)

################################################################################################################################################################
###   regex   ##################################################################################################################################################
################################################################################################################################################################

IP = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

DOVECOT = [
    '^...................  dovecot:  imap'
]

CONNECT = [
    '^...................  dovecot:  master: ',
    '^...................  postfix/master\[',
    '^...................  postfix/postsuper\[',
    '^...................  postfix/postqueue\[',
    '^...................  postfix/pickup\[\d+\]:  [A-F0-9]+: uid=\d+ from=',
    '^...................  postfix/smtp\[\d+\]:  Untrusted TLS connection established to ',
    '^...................  postfix:(25|17465)/smtpd\[\d+\]:  connect from ',
    '^...................  postfix:(25|17465)/smtpd\[\d+\]:  warning: hostname [A-Za-z0-9.-]+ does not resolve to address '
]

GREYLIST = [
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] commands=0\/0',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\].* unknown=0\/\d+',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=0\/\d+ commands=0\/\d+',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] quit=1 commands=1',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] starttls=1 commands=1',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=1 quit=1 commands=2',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=1 rset=1 commands=2',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=1 starttls=1 commands=2',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=2 starttls=1 commands=3',
    '^...................  postfix:25/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=1 starttls=0\/1 commands=1\/2',
    '^...................  postfix:25/smtpd\[\d+\]:  improper command pipelining after \S+ from [A-Za-z0-9.-]+\[{ip}\]',
    '^...................  postfix:25/smtpd\[\d+\]:  warning: hostname [A-Za-z0-9.-]+ does not resolve to address {ip}',
    '^...................  postfix:25/smtpd\[\d+\]:  warning: Connection concurrency limit exceeded: \d+ from [A-Za-z0-9.-]+\[{ip}\]'
]

BLACKLIST = [
    '^...................  postfix/cleanup\[\d+\]:  [A-F0-9]+: reject: header .* from [A-Za-z0-9.-]+\[{ip}\]',
    '^...................  postfix/cleanup\[\d+\]:  [A-F0-9]+: discard: header .* from [A-Za-z0-9.-]+\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  warning: non-SMTP command from [A-Za-z0-9.-]+\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  warning: Illegal address syntax from [A-Za-z0-9.-]+\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.shodan\.io\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.ro\.ovo\.sc\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.stretchoid\.com\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.shadowserver\.org\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.censys-scanner\.com\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.threatsinkhole\.com\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.security\.ipip\.net\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.internet-census\.org\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.security-research\.org\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  connect from [A-Za-z0-9.-]+\.internet-measurement\.com\[{ip}\]',
    '^...................  postfix:\d+/smtpd\[\d+\]:  disconnect from [A-Za-z0-9.-]+\[{ip}\] ehlo=.* auth=0\/\d+ ',
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]: 554 5.7.1 \S+: Relay access denied; ',
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]: 550 5.7.23 \S+: Recipient address rejected: Message rejected due to: SPF fail - not authorized; ',
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]: 450 4.7.1 \S+: Helo command rejected: Host not found; from=\S+ to=<[A-Za-z0-9._-]+@(?!kudlacek\.ch>)[^>]*> ',
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]: 450 4.7.25 Client host rejected: cannot find your hostname, \S+; from=<[A-Za-z0-9._-]+@kudlacek\.ch> ',
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]: 450 4.7.25 Client host rejected: cannot find your hostname, \S+; from=\S+ to=<[A-Za-z0-9._-]+@(?!kudlacek\.ch>)[^>]*> ',
    '^...................  postfix:25/smtpd\[\d+\]:  NOQUEUE: reject: RCPT from [A-Za-z0-9.-]+\[{ip}\]: 504 5.5.2 \S+: Helo command rejected: need fully-qualified hostname; from=\S+ to=<[A-Za-z0-9._-]+@(?!kudlacek\.ch>)[^>]*> '
]

################################################################################################################################################################
###   compiled regex   #########################################################################################################################################
################################################################################################################################################################

DOVECOT_COMPILED = regex.compile('|'.join(DOVECOT))
CONNECT_COMPILED = regex.compile('|'.join(CONNECT))

BLACKLIST_COMPILED = regex.compile('(?|%s)' % '|'.join(BLACKLIST).format(ip=IP))
GREYLIST_COMPILED = regex.compile('(?|%s)' % '|'.join(GREYLIST).format(ip=IP))

################################################################################################################################################################
###   functions   ##############################################################################################################################################
################################################################################################################################################################

def host_lookup(addr):
    try:
        return socket.gethostbyaddr(addr)[0]
    except socket.herror:
        return None
    except:
        return -1

################################################################################################################################################################
###   main   ###################################################################################################################################################
################################################################################################################################################################

logfile = '/var/log/mail/mail.log'

frequency = {}

prev_blacklist = ''
prev_greylist = ''

while True:
    with open(logfile, 'a', buffering=1) as f:

        NL = True	# next line can be newline
        DC = False	# last line was dovecot
        f_ino = os.stat(logfile)[stat.ST_INO]

        ########################################################################################################################################################
        for line in sys.stdin: #################################################################################################################################
        ########################################################################################################################################################

            try:
                if os.stat(logfile)[stat.ST_INO] != f_ino:	# break if file was renamed by logrotate
                    f.write(line)
                    break
            except IOError:
                pass

            ####################################################################################################################################################

            if CONNECT_COMPILED.search(line):
                if NL:
                    f.write('\n')
                    DC = False
            elif DOVECOT_COMPILED.search(line):
                if NL and not DC:
                    f.write('\n')
                DC = True
            else:
                if DC:
                    f.write('\n')
                DC = False

            f.write(line)
            NL = True

            ####################################################################################################################################################

            match = BLACKLIST_COMPILED.search(line)
            if match:
                host_ip = match['ip']
                if host_ip != prev_blacklist:
                    with open("/proc/net/xt_recent/BLACKLIST", 'w') as blacklist:
                        blacklist.write(f'+{host_ip}\n')
                    f.write(f'\n   BLACKLIST:  {host_lookup(host_ip)} [{host_ip}]\n\n')
                    prev_blacklist = host_ip
                    NL = False

            ####################################################################################################################################################

            else:
                match = GREYLIST_COMPILED.search(line)
                if match:
                    host_ip = match['ip']
                    if host_ip != prev_blacklist:
                        with open("/proc/net/xt_recent/GREYLIST", 'w') as blacklist:
                            blacklist.write(f'+{host_ip}\n')
                        if host_ip != prev_greylist:
                            if host_ip in frequency:
                                frequency[host_ip] += 1
                                f.write(f'\n   GREYLIST[{frequency[host_ip]}]:  {host_lookup(host_ip)} [{host_ip}]\n\n')
                            else:
                                frequency[host_ip] = 1
                                f.write(f'\n   GREYLIST:  {host_lookup(host_ip)} [{host_ip}]\n\n')
                            prev_greylist = host_ip
                            NL = False

        ########################################################################################################################################################
        else: ##################################################################################################################################################
        ########################################################################################################################################################

            sys.exit(0)	# exit on EOF


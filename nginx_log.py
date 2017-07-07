#!/usr/bin/python3

import sys

months = {
    'Jan': 1,
    'Feb': 2,
    'Mar': 3,
    'Apr': 4,
    'May': 5,
    'Jun': 6,
    'Jul': 7,
    'Aug': 8,
    'Sep': 9,
    'Oct': 10,
    'Nov': 11,
    'Dec': 12,
}


class Log:
    pass


class Line:
    def __init__(self, s):
        self.s = s
        self.left = 0
        self.right = 0

    def __call__(self, sep=' '):
        self.right = self.s.find(sep, self.left)
        part = self.s[self.left:self.right]
        self.left = self.right + len(sep)
        return part


def parse_raw_log(line, ua):
    line = Line(line)
    log = Log()
    try:
        log.addr = line()
        line()
        log.user = line(' [')
        log.day = int(line('/'))
        log.month = months[line('/')]
        log.year = int(line(':'))
        log.hour = int(line(':'))
        log.minute = int(line(':'))
        log.second = int(line())
        log.timezone = line('] "')
        log.method = line()
        log.path = line()
        log.protocol = line('" ')
        log.code = int(line())
        log.size = int(line(' "'))
        log.referrer = line('" "')
        agent = line('"')
        log.agent = ua.get(agent, agent)
        return log
    except:
        return None


def log_output(log, date=[None, None, None]):
    if log is None:
        return
    if log.agent.endswith('bot'):
        return
    if log.method == 'GET' and log.path in {'/', '/sitemap.xml', '/robots.txt', '/favicon.ico'}:
        return
    if log.code in {400, 404}:
        return
    addr = ''.join(map(lambda s: '%02x' % int(s), log.addr.split('.')))
    if [log.year, log.month, log.day] != date:
        print('===== %04d-%02d-%02d %s =====' % (log.year, log.month, log.day, log.timezone))
        date[:] = [log.year, log.month, log.day]
    print('%02d:%02d %s %-7s %d %-4s %s' % (
        log.hour, log.minute,
        addr, log.agent,
        log.code, log.method, log.path,
    ))


def main():
    path = '/var/log/nginx/access.log'
    if len(sys.argv) > 1:
        path = sys.argv[1]
    with open('known_ua') as f:
        ua = eval(f.read())
    with open(path) as f:
        for line in f:
            log = parse_raw_log(line, ua)
            log_output(log)


if __name__ == '__main__':
    main()

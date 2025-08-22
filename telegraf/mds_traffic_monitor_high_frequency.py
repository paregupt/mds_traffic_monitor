#! /usr/bin/python3
"""Pull stats from Cisco MDS 9000 switches and print output in the
desired output format"""

__author__ = "Paresh Gupta"
__version__ = "0.20"
__updated__ = "22-Aug-2025-6-PM-PDT"

import sys
import os
import argparse
import logging
from logging.handlers import RotatingFileHandler
import json
import time
import re
import concurrent.futures
import requests
import urllib3
import xml.etree.ElementTree as ET

HOURS_IN_DAY = 24
MINUTES_IN_HOUR = 60
SECONDS_IN_MINUTE = 60

user_args = {}
FILENAME_PREFIX = __file__.replace('.py', '')
INPUT_FILE_PREFIX = ''

LOGFILE_LOCATION = '/var/log/telegraf/'
LOGFILE_SIZE = 10000000
LOGFILE_NUMBER = 10
logger = logging.getLogger('MTM')

# Dictionary with key as IP and value as list of user and passwd
switch_dict = {}

# Stats for all switch components are collected here before printing
# in the desired output format
stats_dict = {}

# Used to store objects returned by the stats pull. These must be processed
# to update stats_dict
raw_cli_stats = {}
raw_api_stats = {}

intf_fc_str = ''
intf_pc_str = ''

'''
Tracks response and parsing time
response_time_dict : {
                      'switch_ip' : [
                                        {
                                            'nxapi_start':'time',
                                            'nxapi_rsp':'time',
                                            'nxapi_parse':'time'
                                        },
                                        {
                                            'nxapi_start':'time',
                                            'nxapi_rsp':'time',
                                            'nxapi_parse':'time'
                                        },
                                        ...
                                        As many items as fn_dispatcher
                                        ...
                                        {
                                            'nxapi_start':'time',
                                            'nxapi_rsp':'time',
                                            'nxapi_parse':'time'
                                        },
                                    ]
                      }
'''
response_time_dict = {}

###############################################################################
# BEGIN: Generic functions
###############################################################################

def pre_checks_passed(argv):
    """Python version check"""

    if sys.version_info[0] < 3:
        print('Unsupported with Python 2. Must use Python 3')
        logger.error('Unsupported with Python 2. Must use Python 3')
        return False
    if len(argv) <= 1:
        print('Try -h option for usage help')
        return False

    return True

def parse_cmdline_arguments():
    """Parse input arguments"""

    desc_str = \
    'Pull stats from Cisco MDS switches and print output in different\n' + \
    'formats like InfluxDB Line protocol'
    epilog_str = \
    'This file pulls stats from Cisco MDS and converts them into a\n' + \
    'database insert format. The database can be used by a GUI app like\n' + \
    'Grafana. The initial version was coded to insert into InfluxDB.\n' + \
    'Before converting into any specific format (like InfluxDB Line\n' + \
    'Protocol), the data is correlated in a hierarchical dictionary.\n' + \
    'This dictionary can be parsed to output the data into other formats.\n' + \
    'Overall, the output can be extended for other databases also.\n\n' + \
    'High level steps:\n' + \
    '  - Read access details of a Cisco MDS switches (IP Address, user\n' + \
    '    (read-only is enough) and password) from the input file\n' + \
    '  - Use NX-API or CLI/SSH to pull stats\n'+ \
    '  - Stitch the output for end-to-end traffic mapping and store\n' + \
    '    in a dictionary\n' + \
    '  - Finally, read the dictionary content to print in the desired\n' + \
    '    output format, like InfluxDB Line Protocol'

    parser = argparse.ArgumentParser(description=desc_str, epilog=epilog_str,
                formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input_file', action='store', help='file containing \
            the MDS switch information in the format: IP,user,password')
    parser.add_argument('output_format', action='store', help='specify the \
            output format', choices=['dict', 'influxdb-lp'])
    parser.add_argument('-intfstr', dest='intf_str', \
            action='store_true', default=False, help='Prebuild FC and \
            port-channel interface string to use with show interface command')
    parser.add_argument('-intfcntrstr', dest='intf_cntr_str', \
            action='store_true', default=False, help='Use prebuilt FC and \
            port-channel interface string with show interface counter detail \
            command')
    parser.add_argument('-V', dest='verify_only', \
            action='store_true', default=False, help='verify \
            connection and stats pull but do not print the stats')
    parser.add_argument('-v', dest='verbose', \
            action='store_true', default=False, help='warn and above')
    parser.add_argument('-vv', dest='more_verbose', \
            action='store_true', default=False, help='info and above')
    parser.add_argument('-vvv', dest='most_verbose', \
            action='store_true', default=False, help='debug and above')
    parser.add_argument('-vvvv', dest='raw_dump', \
            action='store_true', default=False, help='Dump raw data')

    args = parser.parse_args()
    user_args['input_file'] = args.input_file
    user_args['output_format'] = args.output_format
    user_args['intf_str'] = args.intf_str
    user_args['intf_cntr_str'] = args.intf_cntr_str
    user_args['cli_json'] = False
    user_args['verify_only'] = args.verify_only
    user_args['verbose'] = args.verbose
    user_args['more_verbose'] = args.more_verbose
    user_args['most_verbose'] = args.most_verbose
    user_args['raw_dump'] = args.raw_dump

    global INPUT_FILE_PREFIX
    INPUT_FILE_PREFIX = ((((user_args['input_file']).split('/'))[-1]).split('.'))[0]

def setup_logging():
    """Setup logging"""

    this_filename = (FILENAME_PREFIX.split('/'))[-1]
    logfile_location = LOGFILE_LOCATION + this_filename
    logfile_prefix = logfile_location + '/' + this_filename
    try:
        os.mkdir(logfile_location)
    except FileExistsError:
        pass
    except Exception:
        # Log in local directory if can't be created in LOGFILE_LOCATION
        logfile_prefix = FILENAME_PREFIX
    finally:
        logfile_name = logfile_prefix + '_' + INPUT_FILE_PREFIX + '.log'
        rotator = RotatingFileHandler(logfile_name, maxBytes=LOGFILE_SIZE,
                                      backupCount=LOGFILE_NUMBER)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        rotator.setFormatter(formatter)
        logger.addHandler(rotator)

        if user_args.get('verbose'):
            logger.setLevel(logging.WARNING)
        if user_args.get('more_verbose'):
            logger.setLevel(logging.INFO)
        if user_args.get('most_verbose') or user_args.get('raw_dump'):
            logger.setLevel(logging.DEBUG)

###############################################################################
# END: Generic functions
###############################################################################

###############################################################################
# BEGIN: Output functions
###############################################################################

def print_output_in_influxdb_lp(switch_ip, per_switch_stats_dict):
    """
    InfluxDB Line Protocol Reference
        * Never double or single quote the timestamp
        * Never single quote field values
        * Do not double or single quote measurement names, tag keys, tag values,
          and field keys
        * Do not double quote field values that are floats, integers, or Booleans
        * Do double quote field values that are strings
        * Performance tips: sort by tag key
    Example: myMeasurement,tag1=tag1val,tag2=tag2val Field1="testData",Field2=3
    """
    final_print_string = ''
    switch_prefix = 'Switches'
    port_prefix = 'SwitchPortStats'

    switch_tags = ''
    switch_fields = ''

    if 'location' in per_switch_stats_dict:
        switch_tags = switch_tags + ',location=' + \
                      per_switch_stats_dict['location']

    switch_tags = switch_tags + ',switch=' + switch_ip

    if 'response_time' in per_switch_stats_dict:
        switch_fields = switch_fields + ' response_time=' + \
                        str(per_switch_stats_dict['response_time'])

    if 'chassis_id' in per_switch_stats_dict:
        switch_fields = switch_fields + ',chassis_id="' + \
                        per_switch_stats_dict['chassis_id'] + '"'

    if 'cpu_kernel' in per_switch_stats_dict:
        switch_fields = switch_fields + ',cpu_kernel=' + \
                        str(per_switch_stats_dict['cpu_kernel'])

    if 'cpu_user' in per_switch_stats_dict:
        switch_fields = switch_fields + ',cpu_user=' + \
                        str(per_switch_stats_dict['cpu_user'])

    if 'load_avg_1min' in per_switch_stats_dict:
        switch_fields = switch_fields + ',load_avg_1min=' + \
                        str(per_switch_stats_dict['load_avg_1min'])

    if 'mem_total' in per_switch_stats_dict:
        switch_fields = switch_fields + ',mem_total=' + \
                        str(per_switch_stats_dict['mem_total'])

    if 'mem_used' in per_switch_stats_dict:
        switch_fields = switch_fields + ',mem_used=' + \
                        str(per_switch_stats_dict['mem_used'])

    if 'sys_ver' in per_switch_stats_dict:
        switch_fields = switch_fields + ',sys_ver="' + \
                        per_switch_stats_dict['sys_ver'] + '"'

    if 'switchname' in per_switch_stats_dict:
        switch_fields = switch_fields + ',switchname="' + \
                      per_switch_stats_dict['switchname'] + '"'

    if 'sys_uptime' in per_switch_stats_dict:
        switch_fields = switch_fields + ',sys_uptime=' + \
                        str(per_switch_stats_dict['sys_uptime'])

    if 'kernel_uptime' in per_switch_stats_dict:
        switch_fields = switch_fields + ',kernel_uptime=' + \
                        str(per_switch_stats_dict['kernel_uptime'])

    if 'active_sup_uptime' in per_switch_stats_dict:
        switch_fields = switch_fields + ',active_sup_uptime=' + \
                        str(per_switch_stats_dict['active_sup_uptime'])

    switch_fields = switch_fields + '\n'
    final_print_string = final_print_string + switch_prefix + \
                         switch_tags + switch_fields

    port_str = ''

    port_dict = per_switch_stats_dict['ports']
    for port, per_port_dict in port_dict.items():
        port_tags = ''
        port_fields = ''

        if 'location' in per_switch_stats_dict:
            port_tags = port_tags + ',location=' + \
                      per_switch_stats_dict['location']

        for key, val in sorted((per_port_dict['meta']).items()):
            # Avoid null tags
            if str(val) == '':
                continue
            port_tags = port_tags + ',' + key + '=' + str(val)

        port_tags = port_tags + ',switch=' + switch_ip + \
                    ',switchport=' + port

        for key, val in sorted((per_port_dict['data']).items()):
            sep = ' ' if port_fields == '' else ','
            if key in ('description', 'pwwn', 'port_down_reason', \
                       'last_changed'):
                port_fields = port_fields + sep + key + '="' + str(val) + '"'
            else:
                port_fields = port_fields + sep + key + '=' + str(val)

        if 'switchname' in per_switch_stats_dict:
            port_fields = port_fields + ',switchname="' + \
                            str(per_switch_stats_dict['switchname']) + '"'

        port_fields = port_fields + '\n'
        port_str = port_str + port_prefix + port_tags + port_fields

    final_print_string = final_print_string + port_str

    print(final_print_string)


def print_output(switch_ip, per_switch_stats_dict):
    """Print outout in the desired output format"""

    if user_args['verify_only']:
        logger.info('Skipping output in %s due to -V option',
                    user_args['output_format'])
        return
    if user_args['output_format'] == 'dict':
        current_log_level = logger.level
        logger.setLevel(logging.DEBUG)
        logger.info('Printing per_switch_stats_dict for %s', switch_ip)
        logger.debug('\n%s', json.dumps(per_switch_stats_dict, indent=2))
        logger.info('Printing output for %s DONE', switch_ip)
        logger.setLevel(current_log_level)
    if user_args['output_format'] == 'influxdb-lp':
        logger.info('Printing output in InfluxDB Line Protocol format')
        print_output_in_influxdb_lp(switch_ip, per_switch_stats_dict)
        logger.info('Printing output - DONE')


###############################################################################
# END: Output functions
###############################################################################

###############################################################################
# BEGIN: Parser functions
###############################################################################

def get_float_from_string(s):
    """
    Clean up function for dirty data. Used for transceiver stats like
    current, voltage, etc.
    """
    ret = ''.join(re.findall(r"[-+]?\d*\.\d+|\d+", s))

    if len(ret) == 0:
        return 0

    return float(ret)

def get_speed_num_from_string(speed):
    """
    Just retain the number in gbps. 32 Gbps => 32, 16 Gbps => 16
    strip off gbps, etc.
    """
    if speed.isdigit():
        return (int)(speed)

    if 'bps' in (str)(speed):
        return (int)(get_float_from_string(speed))

    logger.warning('Unable to parse speed(%s)-----Ignoring ' \
                    'for now and continuing with 0-----\n----------'\
                    'REPORT THIS ISSUE----------', speed,
                   stack_info=True)
    return 0


def parse_sh_ver_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show version
    """
    logger.info('parse_sh_ver_json for %s', switch_ip)

    per_switch_stats_dict['sys_ver'] = cmd_body.get('sys_ver_str')
    per_switch_stats_dict['chassis_id'] = cmd_body.get('chassis_id')
    per_switch_stats_dict['switchname'] = cmd_body.get('host_name')

    logger.info('Done: parse_sh_ver_json for %s', switch_ip)

def parse_sh_ver(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show version
    """
    if user_args['cli_json']:
        parse_sh_ver_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_ver for %s', switch_ip)
    # Hardware
    #  cisco MDS 9710 (10 Slot) Chassis ("Supervisor Module-3")
    per_switch_stats_dict['chassis_id'] = \
                ''.join(re.findall(r'(MDS[ ]{1,}.*Chassis)',
                                   cmd_body, re.IGNORECASE))

    #   System version: 8.4(1a)
    per_switch_stats_dict['sys_ver'] = \
                ''.join(re.findall(r'system:[ ]{1,}version[ ]{1,}(.*)',
                                   cmd_body))

    #   Device name: MDS9710-A
    per_switch_stats_dict['switchname'] = \
                ''.join(re.findall(r'Device name:[ ]{1,}(.*)',
                                   cmd_body, re.IGNORECASE))

    logger.info('Done: parse_sh_ver for %s', switch_ip)


def parse_sh_fcs_ie(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show fcs ie
    """

    logger.info('parse_sh_fcs_ie for %s', switch_ip)

    logger.info('Done: parse_sh_fcs_ie for %s', switch_ip)

def parse_sh_sys_resources_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show system resources
    """
    logger.info('parse_sh_sys_resources_json for %s', switch_ip)

    per_switch_stats_dict['cpu_user'] = cmd_body.get('cpu_state_user')
    per_switch_stats_dict['cpu_kernel'] = cmd_body.get('cpu_state_kernel')
    per_switch_stats_dict['mem_total'] = cmd_body.get('memory_usage_total')
    per_switch_stats_dict['mem_used'] = cmd_body.get('memory_usage_used')
    per_switch_stats_dict['load_avg_1min'] = cmd_body.get('load_avg_1min')

    logger.info('Done: parse_sh_sys_resources_json for %s', switch_ip)

def parse_sh_sys_resources(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show system resources
    """
    if user_args['cli_json']:
        parse_sh_sys_resources_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_sys_resources for %s', switch_ip)

    # Load average:   1 minute: 0.21   5 minutes: 0.33   15 minutes: 0.33
    per_switch_stats_dict['load_avg_1min'] = get_float_from_string(''.join( \
        re.findall(r'Load average:[ ]{1,}1 minute:[ ]{1,}(.*?)5 minutes',
                   cmd_body, re.IGNORECASE)))

    # CPU states  :   5.18% user,   5.18% kernel,   89.63% idle
    cpu_str = ''.join(re.findall(r'CPU states(.*)kernel', \
                                 cmd_body, re.IGNORECASE))
    per_switch_stats_dict['cpu_user'] = get_float_from_string(''.join( \
        re.findall(r'(.*),', cpu_str, re.IGNORECASE)))
    per_switch_stats_dict['cpu_kernel'] = get_float_from_string(''.join( \
        re.findall(r',(.*)', cpu_str, re.IGNORECASE)))

    # Memory usage:   8167876K total,   3906632K used,   4261244K free
    mem_str = ''.join(re.findall(r'Memory usage(.*)used', \
                                 cmd_body, re.IGNORECASE))
    per_switch_stats_dict['mem_total'] = get_float_from_string(''.join( \
        re.findall(r'(.*),', mem_str, re.IGNORECASE)))
    per_switch_stats_dict['mem_used'] = get_float_from_string(''.join( \
        re.findall(r',(.*)', mem_str, re.IGNORECASE)))

    logger.info('Done: parse_sh_sys_resources for %s', switch_ip)


def parse_sh_sys_uptime_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show system uptime
    """
    logger.info('parse_sh_sys_uptime_json for %s', switch_ip)

    sys_uptime_secs = cmd_body.get('sys_up_secs') + \
                  cmd_body.get('sys_up_mins') * SECONDS_IN_MINUTE + \
                  cmd_body.get('sys_up_hrs') * MINUTES_IN_HOUR * \
                                                  SECONDS_IN_MINUTE + \
                  cmd_body.get('sys_up_days') * HOURS_IN_DAY * \
                                                   MINUTES_IN_HOUR * \
                                                   SECONDS_IN_MINUTE
    per_switch_stats_dict['sys_uptime'] = sys_uptime_secs

    kernel_uptime_secs = cmd_body.get('kn_up_secs') + \
                  cmd_body.get('kn_up_mins') * SECONDS_IN_MINUTE + \
                  cmd_body.get('kn_up_hrs') * MINUTES_IN_HOUR * \
                                                  SECONDS_IN_MINUTE + \
                  cmd_body.get('kn_up_days') * HOURS_IN_DAY * \
                                                   MINUTES_IN_HOUR * \
                                                   SECONDS_IN_MINUTE
    per_switch_stats_dict['kernel_uptime'] = kernel_uptime_secs

    logger.info('Done: parse_sh_sys_uptime_json for %s', switch_ip)

def parse_sh_sys_uptime(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show system uptime
    """
    if user_args['cli_json']:
        parse_sh_sys_uptime_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_sys_uptime for %s', switch_ip)
    for line in cmd_body.splitlines():
        if line.startswith('System uptime'):
            sys_uptime_list = line.split(',')
            if len(sys_uptime_list) < 4:
                logger.error('Can\'t parse: %s', line)
                continue
            sys_up_days = int(get_float_from_string(sys_uptime_list[0]))
            sys_up_hrs = int(get_float_from_string(sys_uptime_list[1]))
            sys_up_mins = int(get_float_from_string(sys_uptime_list[2]))
            sys_up_secs = int(get_float_from_string(sys_uptime_list[3]))

            sys_uptime_secs = sys_up_secs + \
                              sys_up_mins * SECONDS_IN_MINUTE + \
                              sys_up_hrs * MINUTES_IN_HOUR * \
                                           SECONDS_IN_MINUTE + \
                              sys_up_days * HOURS_IN_DAY * \
                                            MINUTES_IN_HOUR * \
                                            SECONDS_IN_MINUTE

            per_switch_stats_dict['sys_uptime'] = sys_uptime_secs
        if line.startswith('Kernel uptime'):
            ker_uptime_list = line.split(',')
            if len(ker_uptime_list) < 4:
                logger.error('Unable to parse: %s', line)
                continue
            ker_up_days = int(get_float_from_string(ker_uptime_list[0]))
            ker_up_hrs = int(get_float_from_string(ker_uptime_list[1]))
            ker_up_mins = int(get_float_from_string(ker_uptime_list[2]))
            ker_up_secs = int(get_float_from_string(ker_uptime_list[3]))

            ker_uptime_secs = ker_up_secs + \
                              ker_up_mins * SECONDS_IN_MINUTE + \
                              ker_up_hrs * MINUTES_IN_HOUR * \
                                           SECONDS_IN_MINUTE + \
                              ker_up_days * HOURS_IN_DAY * \
                                            MINUTES_IN_HOUR * \
                                            SECONDS_IN_MINUTE

            per_switch_stats_dict['kernel_uptime'] = ker_uptime_secs
        if line.startswith('Active supervisor uptime'):
            active_sup_uptime_list = line.split(',')
            if len(active_sup_uptime_list) < 4:
                logger.error('Unable to parse: %s', line)
                continue
            sup_up_days = int(get_float_from_string(active_sup_uptime_list[0]))
            sup_up_hrs = int(get_float_from_string(active_sup_uptime_list[1]))
            sup_up_mins = int(get_float_from_string(active_sup_uptime_list[2]))
            sup_up_secs = int(get_float_from_string(active_sup_uptime_list[3]))

            sup_uptime_secs = sup_up_secs + \
                              sup_up_mins * SECONDS_IN_MINUTE + \
                              sup_up_hrs * MINUTES_IN_HOUR * \
                                           SECONDS_IN_MINUTE + \
                              sup_up_days * HOURS_IN_DAY * \
                                            MINUTES_IN_HOUR * \
                                            SECONDS_IN_MINUTE
            per_switch_stats_dict['active_sup_uptime'] = sup_uptime_secs

    logger.info('Done: parse_sh_sys_uptime for %s', switch_ip)

def parse_sh_mod_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show module - JSON
    """
    logger.info('parse_sh_mod_json for %s', switch_ip)

    if 'TABLE_modinfo' not in cmd_body:
        logger.error('TABLE_modinfo not found in cmd_body\n%s', cmd_body)
        return

    if 'ROW_modinfo' not in cmd_body['TABLE_modinfo']:
        logger.error('ROW_modinfo not found in cmd_body\n%s', cmd_body)
        return

    modinfo = cmd_body['TABLE_modinfo']['ROW_modinfo']

    if isinstance(modinfo, dict):
        modinfo = [modinfo]

    module_dict = per_switch_stats_dict['modules']

    global intf_fc_str
    intf_str_list = []
    for item in modinfo:
        if 'model' not in item:
            logger.error('Unable to find model in ROW_modinfo')
            continue

        if 'ports' not in item:
            logger.error('Unable to find ports in ROW_modinfo')
            continue

        if 'modtype' not in item:
            logger.warning('Unable to find modtype in ROW_modinfo')
            continue

        if 'mod' in item:
            mod_num = item['mod']
        elif 'modinf' in item:
            mod_num = item['modinf']
        else:
            logger.error('Unable to find mod/modinf in ROW_modinfo')
            continue

        if '1536K9' in item['model'] or '768K9' in item['model'] or \
            '9132' in item['model'] or '9148T' in item['model'] or \
            '9396T' in item['model'] or '3072K9' in item['model']:
            module_dict[mod_num] = {}
            module_dict[mod_num]['model'] = item['model']
            module_dict[mod_num]['status'] = item['status']
            module_dict[mod_num]['modtype'] = item['modtype']

            intf_str = 'fc' +  str(mod_num) + '/' + '1 - ' + str(item['ports'])
            intf_str_list.append(intf_str)

        if 'X9334-K9' in item['model']:
            module_dict[mod_num] = {}
            module_dict[mod_num]['model'] = item['model']
            module_dict[mod_num]['status'] = item['status']
            module_dict[mod_num]['modtype'] = item['modtype']

            intf_str = 'fc' +  str(mod_num) + '/' + '1 - 24'
            intf_str_list.append(intf_str)

        if 'SF' in item['model']:
            module_dict[mod_num] = {}
            module_dict[mod_num]['model'] = item['model']
            module_dict[mod_num]['status'] = item['status']
            module_dict[mod_num]['modtype'] = item['modtype']

    intf_fc_str = ' , '.join(intf_str_list)

    logger.info('Done: parse_sh_mod_json for %s %s', switch_ip, intf_fc_str)

def parse_sh_mod(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show module - raw output, not JSON or XML
    """
    if user_args['cli_json']:
        parse_sh_mod_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_mod for %s', switch_ip)
    module_dict = per_switch_stats_dict['modules']

    global intf_fc_str

    mod_cnt = 0
    intf_str_list = []
    col_width_list = []
    for line in cmd_body.splitlines():
        # Mod  Ports  Module-Type                         Model              Status
        if line.startswith('Mod'):
            mod_cnt = mod_cnt + 1
            if mod_cnt > 1:
                break
        elif line.startswith('--'):
            #---  -----  ----------------------------------- ------------------ ----------
            line_list = line.split()
            if len(line_list) < 5:
                logger.error('Unable to parse: %s', cmd_body)
                return
            col_width_list = [len(dash) for dash in line_list]
        else:
            #5    0      Supervisor Module-3                 DS-X97-SF1-K9      active *
            #7    0      1/10 Gbps Ethernet Module                              powered-dn
            #1    48     2/4/8/10/16 Gbps Advanced FC Module DS-X9448-768K9     ok
            # ['1', '48', '2/4/8/10/16', 'Gbps', 'Advanced', 'FC', 'Module', 'DS-X9448-768K9', 'ok']
            if len(col_width_list) < 5:
                logger.error('Corrupt col_width_list for show module', cmd_body)
                continue

            if len(line) < col_width_list[0] + col_width_list[1]:
                continue

            slot = int(line[0:col_width_list[0] + 1])
            num_port = int(line[col_width_list[0]: \
                                col_width_list[0] + col_width_list[1] + 1])
            # 2 + 2 spaces between Mod  Ports  Module-Type
            # 1 and 1 space between Module-Type Model Status
            modtype = (line[col_width_list[0] + col_width_list[1]: \
                            col_width_list[0] + col_width_list[1] + \
                            col_width_list[2] + 4]).strip()
            model = (line[col_width_list[0] + col_width_list[1] + \
                          col_width_list[2] + 4:col_width_list[0] + \
                          col_width_list[1] + col_width_list[2] + \
                          col_width_list[3] + 5]).strip()
            status = (line[col_width_list[0] + col_width_list[1] + \
                           col_width_list[2] + col_width_list[3] + 6:]).strip()
            if '*' in status:
                status = (status.strip('*')).strip()

            module_dict[slot] = {}
            module_dict[slot]['model'] = model
            module_dict[slot]['status'] = status
            module_dict[slot]['modtype'] = modtype

            if '1536K9' in model or '768K9' in model or '9132' in model or \
                '9148T' in model or '9396T' in model or '9148S' in model or \
                '9396S' in model or '3072K9' in model:
                intf_str = 'fc' + str(slot) + '/' + '1 - ' + str(num_port)
                intf_str_list.append(intf_str)

            if '9250' in model:
                intf_str = 'fc1/1 - 40'
                intf_str_list.append(intf_str)

            if 'X9334-K9' in model:
                intf_str = 'fc' +  str(slot) + '/' + '1 - 24'
                intf_str_list.append(intf_str)

    intf_fc_str = ' , '.join(intf_str_list)

    logger.info('Done: parse_sh_mod for %s %s', switch_ip, intf_fc_str)

def parse_sh_portc_u(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show port-channel usage - raw output, not JSON or XML
    """
    logger.info('parse_sh_portc_u for %s', switch_ip)
    global intf_pc_str

    pc_used = re.findall(r'\d+', (''.join(re.findall(r'Used(.*)\n', cmd_body))))
    #pc_used = re.findall(r'\d+', ((re.search('Used(.*)\n', cmd_body)).group(1)))
    pc_list = ['port-channel ' + num for num in pc_used]
    intf_pc_str = ' , '.join(pc_list)

    logger.info('Done: parse_sh_portc_u for %s %s', switch_ip, intf_pc_str)

def parse_sh_int_counters_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface counters detail
    """

    logger.info('parse_sh_int_counters_json for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']
    if 'sys_ver' not in per_switch_stats_dict:
        logger.warning('sys_ver not found for %s', switch_ip)
    else:
        logger.info('NX-OS version for %s: %s', switch_ip,
                                             per_switch_stats_dict['sys_ver'])

    if 'TABLE_counters' not in cmd_body:
        logger.error('TABLE_counters not found in cmd_body\n%s', cmd_body)
        return

    if isinstance(cmd_body['TABLE_counters'], dict):
        cmd_body['TABLE_counters'] = [cmd_body['TABLE_counters']]

    for tc in cmd_body['TABLE_counters']:
        if 'ROW_counters' not in tc:
            logger.error('ROW_counters not found in cmd_body\n%s', cmd_body)
            continue

        if isinstance(tc['ROW_counters'], dict):
            tc['ROW_counters'] = [tc['ROW_counters']]

        for rc in tc['ROW_counters']:
            if 'interface' in rc:
                logger.debug('Found interface %s in %s',
                             rc['interface'], switch_ip)
                interface = rc['interface']
            elif 'interface_sfp' in rc:
                logger.debug('Found interface_sfp %s in %s',
                             rc['interface_sfp'], switch_ip)
                interface = rc['interface_sfp']
            else:
                logger.error('interface not found in cmd_body')
                continue

            if 'fc' not in interface:
                if 'channel' not in interface:
                    logger.debug('Skipping %s on %s', interface, switch_ip)
                    continue
            else:
                intf_list = interface.split('/')
                port_id = intf_list[1]
                if len(port_id) == 1:
                    port_id = '0' + port_id
                    interface = intf_list[0] + '/' + port_id

            if interface not in port_dict:
                port_dict[interface] = {}
            per_port_dict = port_dict[interface]

            if 'data' not in per_port_dict:
                per_port_dict['data'] = {}
            data_dict = per_port_dict['data']

            # Data format before NX-OS 8.4(2)
            if 'TABLE_frames' in rc:
                # Different data format
                if 'ROW_frames' in rc['TABLE_frames']:
                    for rf in rc['TABLE_frames']['ROW_frames']:
                        if 'bytes_rcv' in rf:
                            data_dict['rx_bytes'] = rf['bytes_rcv']
                        if 'bytes_tran' in rf:
                            data_dict['tx_bytes'] = rf['bytes_tran']

                if 'credit_loss' in rc:
                    data_dict['credit_loss'] = rc['credit_loss']

                # Spelling mistake in incoming data :(
                if 'link_faliures' in rc:
                    data_dict['link_failures'] = rc['link_faliures']

                if 'sync_loss' in rc:
                    data_dict['sync_loss'] = rc['sync_loss']

                if 'signal_loss' in rc:
                    data_dict['signal_loss'] = rc['signal_loss']

                if 'inv_trans_err' in rc:
                    data_dict['itw'] = rc['inv_trans_err']

                if 'inv_crc' in rc:
                    data_dict['crc'] = rc['inv_crc']

                if 'link_reset_rcvd' in rc:
                    data_dict['rx_lr'] = rc['link_reset_rcvd']

                if 'link_reset_trans' in rc:
                    data_dict['tx_lr'] = rc['link_reset_trans']

                if 'link_reset_resp_rcvd' in rc:
                    data_dict['rx_lrr'] = rc['link_reset_resp_rcvd']

                if 'link_reset_resp_trans' in rc:
                    data_dict['tx_lrr'] = rc['link_reset_resp_trans']

                if 'txwait' in rc:
                    data_dict['txwait'] = rc['txwait']

                if 'txwait_vl0' in rc:
                    data_dict['txwait_vl0'] = int(rc['txwait_vl0'])

                if 'txwait_vl1' in rc:
                    data_dict['txwait_vl1'] = int(rc['txwait_vl1'])

                if 'txwait_vl2' in rc:
                    data_dict['txwait_vl2'] = int(rc['txwait_vl2'])

                if 'txwait_vl3' in rc:
                    data_dict['txwait_vl3'] = int(rc['txwait_vl3'])

                if 'b2b_credits_transmit' in rc:
                    data_dict['tx_b2b_credit_to_zero'] = \
                                        rc['b2b_credits_transmit']
                if 'b2b_credits_receive' in rc:
                    data_dict['rx_b2b_credit_to_zero'] = \
                                        rc['b2b_credits_receive']

                if 'b2b_credits_transmit_vl0' in rc:
                    data_dict['tx_b2b_credit_to_zero_vl0'] = \
                                        int(rc['b2b_credits_transmit_vl0'])

                if 'b2b_credits_transmit_vl1' in rc:
                    data_dict['tx_b2b_credit_to_zero_vl1'] = \
                                        int(rc['b2b_credits_transmit_vl1'])

                if 'b2b_credits_transmit_vl2' in rc:
                    data_dict['tx_b2b_credit_to_zero_vl2'] = \
                                        int(rc['b2b_credits_transmit_vl2'])

                if 'b2b_credits_transmit_vl3' in rc:
                    data_dict['tx_b2b_credit_to_zero_vl3'] = \
                                        int(rc['b2b_credits_transmit_vl3'])

                if 'b2b_credits_receive_vl0' in rc:
                    data_dict['rx_b2b_credit_to_zero_vl0'] = \
                                        int(rc['b2b_credits_receive_vl0'])

                if 'b2b_credits_receive_vl1' in rc:
                    data_dict['rx_b2b_credit_to_zero_vl1'] = \
                                        int(rc['b2b_credits_receive_vl1'])

                if 'b2b_credits_receive_vl2' in rc:
                    data_dict['rx_b2b_credit_to_zero_vl2'] = \
                                        int(rc['b2b_credits_receive_vl2'])

                if 'b2b_credits_receive_vl3' in rc:
                    data_dict['rx_b2b_credit_to_zero_vl3'] = \
                                        int(rc['b2b_credits_receive_vl3'])

                if 'b2b_credits_receive_vl4' in rc:
                    data_dict['rx_b2b_credit_to_zero_vl4'] = \
                                        int(rc['b2b_credits_receive_vl4'])

                if 'fec_corrected' in rc:
                    data_dict['fec_corrected'] = \
                        int(get_float_from_string(str(rc['fec_corrected'])))

                if 'fec_uncorrected' in rc:
                    data_dict['fec_uncorrected'] = \
                        int(get_float_from_string(str(rc['fec_uncorrected'])))

                if 'timeout_discards' in rc:
                    data_dict['timeout_discards'] = rc['timeout_discards']

            elif 'TABLE_totals' in rc or 'TABLE_total' in rc:
                # Data format in NX-OS 8.4(2) and onwards.
                # totals and total may be returned
                # Total Stats:
                if 'TABLE_totals' in rc:
                    tt = rc['TABLE_totals']
                else:
                    tt = rc['TABLE_total']

                if 'ROW_totals' in tt or 'ROW_total' in tt:
                    if 'ROW_totals' in tt:
                        rt = tt['ROW_totals']
                    else:
                        rt = tt['ROW_total']

                    if isinstance(rt, dict):
                        rt = [rt]

                    rt = rt[0]

                    if 'rx_total_bytes' in rt:
                        data_dict['rx_bytes'] = rt['rx_total_bytes']

                    if 'rx_bytes' in rt:
                        data_dict['rx_bytes'] = rt['rx_bytes']

                    if 'tx_total_bytes' in rt:
                        data_dict['tx_bytes'] = rt['tx_total_bytes']

                    if 'tx_bytes' in rt:
                        data_dict['tx_bytes'] = rt['tx_bytes']

                    if 'rx_total_discard' in rt:
                        data_dict['rx_discard'] = rt['rx_total_discard']

                    if 'rx_discard_frames' in rt:
                        data_dict['rx_discard'] = rt['rx_discard_frames']

                    if 'tx_total_discard' in rt:
                        data_dict['tx_discard'] = rt['tx_total_discard']

                    if 'tx_discard_frames' in rt:
                        data_dict['tx_discard'] = rt['tx_discard_frames']

                    if 'rx_error_frames' in rt:
                        data_dict['rx_error'] = rt['rx_error_frames']

                    if 'rx_total_error' in rt:
                        data_dict['rx_error'] = rt['rx_total_error']

                    if 'tx_error_frames' in rt:
                        data_dict['tx_error'] = rt['tx_error_frames']

                    if 'tx_total_error' in rt:
                        data_dict['tx_error'] = rt['tx_total_error']

                # Link Stats
                if 'TABLE_link' in rc:
                    tl = rc['TABLE_link']
                    if 'ROW_link' in tl:
                        rl = tl['ROW_link']

                        if isinstance(rl, dict):
                            rl = [rl]

                        rl = rl[0]

                        if 'rx_link_failures' in rl:
                            data_dict['link_failures'] = rl['rx_link_failures']

                        if 'link_failures' in rl:
                            data_dict['link_failures'] = rl['link_failures']

                        if 'rx_sync_loss' in rl:
                            data_dict['sync_loss'] = rl['rx_sync_loss']

                        if 'sync_loss' in rl:
                            data_dict['sync_loss'] = rl['sync_loss']

                        if 'rx_signal_loss' in rl:
                            data_dict['signal_loss'] = rl['rx_signal_loss']

                        if 'signal_loss' in rl:
                            data_dict['signal_loss'] = rl['signal_loss']

                        if 'rx_inv_trans_err' in rl:
                            data_dict['itw'] = rl['rx_inv_trans_err']

                        if 'inv_trans_err' in rl:
                            data_dict['itw'] = rl['inv_trans_err']

                        if 'rx_inv_crc' in rl:
                            data_dict['crc'] = rl['rx_inv_crc']

                        if 'inv_crc' in rl:
                            data_dict['crc'] = rl['inv_crc']

                        if 'rx_fec_corrected' in rl:
                            data_dict['fec_corrected'] = \
                                                    rl['rx_fec_corrected']

                        if 'fec_corrected' in rl:
                            data_dict['fec_corrected'] = \
                                                    rl['fec_corrected']

                        if 'rx_fec_uncorrected' in rl:
                            data_dict['fec_uncorrected'] = \
                                                    rl['rx_fec_uncorrected']

                        if 'fec_uncorrected' in rl:
                            data_dict['fec_uncorrected'] = \
                                                    rl['fec_uncorrected']

                        if 'rx_link_reset' in rl:
                            data_dict['rx_lr'] = rl['rx_link_reset']

                        if 'tx_link_reset' in rl:
                            data_dict['tx_lr'] = rl['tx_link_reset']

                        if 'rx_link_reset_resp' in rl:
                            data_dict['rx_lrr'] = rl['rx_link_reset_resp']

                        if 'tx_link_reset_resp' in rl:
                            data_dict['tx_lrr'] = rl['tx_link_reset_resp']

               # Congestion Stats
                if 'TABLE_congestion' in rc:
                    tcon = rc['TABLE_congestion']
                    if 'ROW_congestion' in tcon:
                        rcon = tcon['ROW_congestion']

                        if isinstance(rcon, dict):
                            rcon = [rcon]

                        rcon = rcon[0]

                        if 'tx_timeout_discards' in rcon:
                            data_dict['timeout_discards'] = \
                                                    rcon['tx_timeout_discards']

                        if 'timeout_discards' in rcon:
                            data_dict['timeout_discards'] = \
                                                    rcon['timeout_discards']

                        if 'tx_credit_loss' in rcon:
                            data_dict['credit_loss'] = rcon['tx_credit_loss']

                        if 'credit_loss' in rcon:
                            data_dict['credit_loss'] = rcon['credit_loss']

                        if 'txwait' in rcon:
                            data_dict['txwait'] = rcon['txwait']

                        if 'rx_b2b_credit_remain' in rcon:
                            data_dict['rx_b2b_credit_remain'] = \
                                                    rcon['rx_b2b_credit_remain']

                        if 'tx_b2b_credit_remain' in rcon:
                            data_dict['tx_b2b_credit_remain'] = \
                                                    rcon['tx_b2b_credit_remain']

                        if 'rx_b2b_credit_to_zero' in rcon:
                            data_dict['rx_b2b_credit_to_zero'] = \
                                                    rcon['rx_b2b_credit_to_zero']

                        # Same as above, just different NX-OS
                        if 'rx_b2b_credits' in rcon:
                            data_dict['rx_b2b_credit_to_zero'] = \
                                                    rcon['rx_b2b_credits']

                        if 'tx_b2b_credit_to_zero' in rcon:
                            data_dict['tx_b2b_credit_to_zero'] = \
                                                    rcon['tx_b2b_credit_to_zero']

                        # Same as above, just different NX-OS
                        if 'tx_b2b_credits' in rcon:
                            data_dict['tx_b2b_credit_to_zero'] = \
                                                    rcon['tx_b2b_credits']
            else:
                logger.error('Unable to decode body:%s in %s',
                             interface, cmd_body)
                continue

    logger.info('Done: parse_sh_int_counters_json for %s', switch_ip)

def fill_data_from_sh_int_count_det_842(per_port_dict, intf_body):
    """
    Parse raw output of show interface counter detail, NX-OS 8.4(2) onwards
    """

    if 'data' not in per_port_dict:
        per_port_dict['data'] = {}
    data_dict = per_port_dict['data']

    # negative lookbehind assertion to fin
    # 3818671652 frames, 6845929020368 bytes received
    # not
    # 3818409523 class-3 frames, 6845909666604 bytes received
    '''
    rx_bytes = ''.join(re.findall(r'Rx total bytes:[ ]{1,}(\d+)', intf_body))
    if rx_bytes != '':
        data_dict['rx_bytes'] = rx_bytes

    tx_bytes = ''.join(re.findall(r'Tx total bytes:[ ]{1,}(\d+)', intf_body))
    if tx_bytes != '':
        data_dict['tx_bytes'] = tx_bytes
    '''

    credit_loss = ''.join(re.findall(r'Credit loss:[ ]{1,}(\d+)', intf_body))
    if credit_loss != '':
        data_dict['credit_loss'] = credit_loss

    link_failures = ''.join(re.findall(r'Link failures:[ ]{1,}(\d+)', \
                                       intf_body))
    if link_failures != '':
        data_dict['link_failures'] = link_failures

    sync_loss = ''.join(re.findall(r'Sync losses:[ ]{1,}(\d+)', intf_body))
    if sync_loss != '':
        data_dict['sync_loss'] = sync_loss

    signal_loss = ''.join(re.findall(r'Signal losses:[ ]{1,}(\d+)', intf_body))
    if signal_loss != '':
        data_dict['signal_loss'] = signal_loss

    itw = ''.join(re.findall(r'Invalid transmission words:[ ]{1,}(\d+)', \
                             intf_body))
    if itw != '':
        data_dict['itw'] = itw

    crc = ''.join(re.findall(r'Invalid CRCs:[ ]{1,}(\d+)', intf_body))
    if crc != '':
        data_dict['crc'] = crc

    rx_lr = ''.join(re.findall(r'Rx.*\(LR\).*:[ ]{1,}(\d+)', intf_body))
    if rx_lr != '':
        data_dict['rx_lr'] = rx_lr

    tx_lr = ''.join(re.findall(r'Tx.*\(LR\).*:[ ]{1,}(\d+)', \
                               intf_body))
    if tx_lr != '':
        data_dict['tx_lr'] = tx_lr

    rx_lrr = ''.join(re.findall(r'Rx.*\(LRR\).*:[ ]{1,}(\d+)', \
                                intf_body))
    if rx_lrr != '':
        data_dict['rx_lrr'] =rx_lrr

    tx_lrr = ''.join(re.findall(r'Rx.*\(LRR\).*:[ ]{1,}(\d+)', intf_body))
    if tx_lrr != '':
        data_dict['tx_lrr'] = tx_lrr

    fec_corrected = ''.join(re.findall(r'FEC corrected.*:[ ]{1,}(\d+)', \
                                       intf_body))
    if fec_corrected != '':
        data_dict['fec_corrected'] = fec_corrected

    fec_uncorrected = ''.join(re.findall(r'FEC uncorrected.*:[ ]{1,}(\d+)', \
                                         intf_body))
    if fec_uncorrected != '':
        data_dict['fec_uncorrected'] = fec_uncorrected

    timeout_discards = ''.join(re.findall(r'Timeout discards:[ ]{1,}(\d+)', \
                                          intf_body))
    if timeout_discards != '':
        data_dict['timeout_discards'] = timeout_discards

    rx_discard = ''.join(re.findall(r'Rx total discards:[ ]{1,}(\d+)', \
                                    intf_body))
    if rx_discard != '':
        data_dict['rx_discard'] = rx_discard

    tx_discard = ''.join(re.findall(r'Tx total discards:[ ]{1,}(\d+)', \
                                    intf_body))
    if tx_discard != '':
        data_dict['tx_discard'] = tx_discard

    rx_error = ''.join(re.findall(r'Rx total errors:[ ]{1,}(\d+)', intf_body))
    if rx_error != '':
        data_dict['rx_error'] = rx_error

    tx_error = ''.join(re.findall(r'Tx total errors:[ ]{1,}(\d+)', intf_body))
    if tx_error != '':
        data_dict['tx_error'] = tx_error

    if 'VL' in intf_body:
        # Add the values of all the VLs
        txwait_list = re.findall(r'TxWait 2\.5us.*:[ ]{1,}(\d+)', intf_body)
        txwait = 0
        for per_vl_txwait in txwait_list:
            txwait = txwait + int(per_vl_txwait)
        data_dict['txwait'] = str(txwait)

        tx_b2b_list = re.findall(r'Tx.*transi.*:[ ]{1,}(\d+)', intf_body)
        tx_b2b_credit_to_zero = 0
        for per_vl_tx_b2b in tx_b2b_list:
            tx_b2b_credit_to_zero = tx_b2b_credit_to_zero + int(per_vl_tx_b2b)
        data_dict['tx_b2b_credit_to_zero'] = str(tx_b2b_credit_to_zero)

        rx_b2b_list = re.findall(r'Rx.*transi.*:[ ]{1,}(\d+)', intf_body)
        rx_b2b_credit_to_zero = 0
        for per_vl_rx_b2b in rx_b2b_list:
            rx_b2b_credit_to_zero = rx_b2b_credit_to_zero + int(per_vl_rx_b2b)
        data_dict['rx_b2b_credit_to_zero'] = str(rx_b2b_credit_to_zero)
    else:
        txwait = ''.join(re.findall(r'TxWait 2\.5us.*:[ ]{1,}(\d+)', intf_body))
        if txwait != '':
            data_dict['txwait'] = txwait

        tx_b2b_credit_to_zero = ''.join(re.findall(r'Tx.*zero:[ ]{1,}(\d+)', \
                                                   intf_body))
        if tx_b2b_credit_to_zero != '':
            data_dict['tx_b2b_credit_to_zero'] = tx_b2b_credit_to_zero

        rx_b2b_credit_to_zero = ''.join(re.findall(r'Rx.*zero:[ ]{1,}(\d+)', \
                                                   intf_body))
        if rx_b2b_credit_to_zero != '':
            data_dict['rx_b2b_credit_to_zero'] = rx_b2b_credit_to_zero

def fill_data_from_sh_int_count_det(per_port_dict, intf_body):
    """
    show interface counters detail - raw output, not JSON or XML
    """

    if 'data' not in per_port_dict:
        per_port_dict['data'] = {}
    data_dict = per_port_dict['data']

    # negative lookbehind assertion to find
    # 3818671652 frames, 6845929020368 bytes received
    # not
    # 3818409523 class-3 frames, 6845909666604 bytes received
    '''
    Get as much data as possible from show interface because the chance of not
    working is higher with counter detail command
    rx_bytes = ''.join(re.findall(r'(\d+) bytes received', \
               ''.join(re.findall( \
                r'(?<!class-)\d+ frames, \d+ bytes received', intf_body))))
    if rx_bytes != '':
        data_dict['rx_bytes'] = rx_bytes

    tx_bytes = ''.join(re.findall(r'(\d+) bytes transmitted', \
               ''.join(re.findall( \
                r'(?<!class-)\d+ frames, \d+ bytes transmitted', intf_body))))
    if tx_bytes != '':
        data_dict['tx_bytes'] = tx_bytes
    '''

    credit_loss = ''.join(re.findall(r'(\d+)[ ]{1,}credit loss', intf_body))
    if credit_loss != '':
        data_dict['credit_loss'] = credit_loss

    link_failures = ''.join(re.findall(r'(\d+)[ ]{1,}link failure', intf_body))
    if link_failures != '':
        data_dict['link_failures'] = link_failures

    sync_loss = ''.join(re.findall(r'(\d+)[ ]{1,}sync loss', intf_body))
    if sync_loss != '':
        data_dict['sync_loss'] = sync_loss

    signal_loss = ''.join(re.findall(r'(\d+)[ ]{1,}signal loss', intf_body))
    if signal_loss != '':
        data_dict['signal_loss'] = signal_loss

    itw = ''.join(re.findall(r'(\d+)[ ]{1,}invalid transmission word', \
                             intf_body))
    if itw != '':
        data_dict['itw'] = itw

    crc = ''.join(re.findall(r'(\d+)[ ]{1,}invalid CRC', intf_body))
    if crc != '':
        data_dict['crc'] = crc

    rx_lr = ''.join(re.findall(r'(\d+)[ ]{1,}link reset received', intf_body))
    if rx_lr != '':
        data_dict['rx_lr'] = rx_lr

    tx_lr = ''.join(re.findall(r'(\d+)[ ]{1,}link reset transmitted', \
                               intf_body))
    if tx_lr != '':
        data_dict['tx_lr'] = tx_lr

    rx_lrr = ''.join(re.findall(r'(\d+)[ ]{1,}link reset responses received', \
                                intf_body))
    if rx_lrr != '':
        data_dict['rx_lrr'] =rx_lrr

    tx_lrr = ''.join(re.findall( \
                 r'(\d+)[ ]{1,}link reset responses transmitted', intf_body))
    if tx_lrr != '':
        data_dict['tx_lrr'] = tx_lrr

    fec_corrected = ''.join(re.findall(r'(\d+)[ ]{1,}fec corrected', intf_body))
    if fec_corrected != '':
        data_dict['fec_corrected'] = fec_corrected

    fec_uncorrected = ''.join(re.findall(r'(\d+)[ ]{1,}fec uncorrected', \
                                         intf_body))
    if fec_uncorrected != '':
        data_dict['fec_uncorrected'] = fec_uncorrected

    timeout_discards = ''.join(re.findall(r'(\d+)[ ]{1,}timeout discards', \
                                          intf_body))
    if timeout_discards != '':
        data_dict['timeout_discards'] = timeout_discards

    rx_discard = ''.join(re.findall(r'(\d+)[ ]{1,}discards,.*received', \
                                    intf_body))
    if rx_discard != '':
        data_dict['rx_discard'] = rx_discard

    tx_discard = ''.join(re.findall(r'(\d+)[ ]{1,}discards,.*transmitted', \
                                    intf_body))
    if tx_discard != '':
        data_dict['tx_discard'] = tx_discard

    rx_error = ''.join(re.findall(r'(\d+)[ ]{1,}errors received', intf_body))
    if rx_error != '':
        data_dict['rx_error'] = rx_error

    tx_error = ''.join(re.findall(r'(\d+)[ ]{1,}errors transmitted', intf_body))
    if tx_error != '':
        data_dict['tx_error'] = tx_error

    if 'VL' in intf_body:
        # Add the values of all the VLs
        txwait_list = re.findall(r'TxWait .* VL 0-3:(.*)', intf_body)
        if len(txwait_list) != 0:
            txwait_list_1 = (''.join(txwait_list)).split(',')
            txwait = 0
            for per_vl_txwait in txwait_list_1:
                txwait = txwait + int(per_vl_txwait)
        else:
            # Sometimes combined TxWait is returned even if VLs are enabled
            txwait = ''.join(re.findall(r'(\d+)[ ]{1,}2\.5us TxWait', \
                                        intf_body))
            logger.warning('Found VL but TxWait not found in VL')

        tx_b2b_list = (''.join(re.findall( \
                               r'Transmit B2B .* transitions .* VL 0-3:(.*)', \
                               intf_body))).split(',')
        tx_b2b_credit_to_zero = 0
        for per_vl_tx_b2b in tx_b2b_list:
            tx_b2b_credit_to_zero = tx_b2b_credit_to_zero + int(per_vl_tx_b2b)
        data_dict['tx_b2b_credit_to_zero'] = str(tx_b2b_credit_to_zero)

        rx_b2b_list = (''.join(re.findall( \
                               r'Receive B2B .* transitions .* VL 0-3:(.*)', \
                               intf_body))).split(',')
        rx_b2b_credit_to_zero = 0
        for per_vl_rx_b2b in rx_b2b_list:
            rx_b2b_credit_to_zero = rx_b2b_credit_to_zero + int(per_vl_rx_b2b)
        data_dict['rx_b2b_credit_to_zero'] = str(rx_b2b_credit_to_zero)
    else:
        txwait = ''.join(re.findall(r'(\d+)[ ]{1,}2\.5us TxWait', intf_body))
        if txwait != '':
            data_dict['txwait'] = txwait

        tx_b2b_credit_to_zero = ''.join(re.findall(r'(\d+)[ ]{1,}Transmit B2B', \
                                                   intf_body))
        if tx_b2b_credit_to_zero != '':
            data_dict['tx_b2b_credit_to_zero'] = tx_b2b_credit_to_zero

        rx_b2b_credit_to_zero = ''.join(re.findall(r'(\d+)[ ]{1,}Receive B2B', \
                                                   intf_body))
        if rx_b2b_credit_to_zero != '':
            data_dict['rx_b2b_credit_to_zero'] = rx_b2b_credit_to_zero

def parse_sh_int_counters(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface counters detail
    """
    if user_args['cli_json']:
        parse_sh_int_counters_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_int_counters for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']
    if 'sys_ver' not in per_switch_stats_dict:
        logger.error('Must need sys_ver to parse counters detail:%s', switch_ip)
        return

    sys_ver = per_switch_stats_dict['sys_ver']
    logger.info('NX-OS version for %s is %s', switch_ip,
                                              per_switch_stats_dict['sys_ver'])

    # Output changed in NX-OS 8.4(2)
    if sys_ver < '8.4(2)':
        # Use ? for non-greedy match
        fc_cmd_list = re.findall(r'fc.*?Percentage TxWait', cmd_body, re.DOTALL)
        pc_list = re.findall(r'port-channel.*?Percentage TxWait', cmd_body,\
                                                                      re.DOTALL)
        '''
        The 2nd clean-up of port-channel counter detail is required to handle
        FCIP port-channel in following format:
            <some counters for fcip port-channel>
            <some counters for fcip port-channel>
        port-channel1
            <some counters for fcip port-channel>
            <some counters for fcip port-channel>
        port-channel2
        port-channel3
            <some counters for fc port-channel>
            <some counters for fc port-channel>
        port-channel4
            <some counters for fc port-channel>
            <some counters for fc port-channel>

        This ignores the FCIP port-channels
        '''
        pc_cmd_list = []
        for cmd_output in pc_list:
            pc_cmd_list.append(''.join(re.findall(r'.*(port-channel.*)', \
                                                  cmd_output, re.DOTALL)))

        for fc_intf in fc_cmd_list:
            interface = ''.join(re.findall(r'(fc\d+/\d+)', fc_intf))
            intf_list = interface.split('/')
            if len(intf_list) < 2:
                logger.error('Unable to parse:%s', fc_intf)
                continue
            port_id = intf_list[1]
            if len(port_id) == 1:
                port_id = '0' + port_id
                interface = intf_list[0] + '/' + port_id

            logger.debug('Filling %s-', interface)
            if interface not in port_dict:
                port_dict[interface] = {}
            per_port_dict = port_dict[interface]

            fill_data_from_sh_int_count_det(per_port_dict, fc_intf)

        for pc_intf in pc_cmd_list:
            interface = ''.join(re.findall(r'(port-channel\d+)', pc_intf))
            logger.debug('Filling %s-', interface)
            if interface not in port_dict:
                port_dict[interface] = {}
            per_port_dict = port_dict[interface]

            fill_data_from_sh_int_count_det(per_port_dict, pc_intf)
    else:
        # NX-OS 8.4(2) onwards
        fc_cmd_list = re.findall(r'fc.*?Last clearing', cmd_body, re.DOTALL)
        # Look for \n\n after Congestion Stats
        pc_cmd_list = re.findall(r'port-channel.*?Congestion Stats.*?\n\n',\
                                 cmd_body, re.DOTALL)

        for fc_intf in fc_cmd_list:
            interface = ''.join(re.findall(r'(fc\d+/\d+)', fc_intf))
            intf_list = interface.split('/')
            if len(intf_list) < 2:
                logger.error('Unable to parse:%s', fc_intf)
                continue
            port_id = intf_list[1]
            if len(port_id) == 1:
                port_id = '0' + port_id
                interface = intf_list[0] + '/' + port_id

            logger.debug('Filling %s-', interface)
            if interface not in port_dict:
                port_dict[interface] = {}
            per_port_dict = port_dict[interface]

            fill_data_from_sh_int_count_det_842(per_port_dict, fc_intf)

        for pc_intf in pc_cmd_list:
            interface = ''.join(re.findall(r'(port-channel\d+)', pc_intf))
            logger.debug('Filling %s-', interface)
            if interface not in port_dict:
                port_dict[interface] = {}
            per_port_dict = port_dict[interface]

            fill_data_from_sh_int_count_det_842(per_port_dict, pc_intf)


    logger.info('Done: parse_sh_int_counters for %s', switch_ip)

def parse_sh_int_trans_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface transceiver detail
    """
    logger.info('parse_sh_int_trans_json for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']
    if 'sys_ver' not in per_switch_stats_dict:
        logger.warning('sys_ver not found for %s', switch_ip)
    else:
        logger.info('NX-OS version for %s: %s', switch_ip,
                                             per_switch_stats_dict['sys_ver'])

    if 'TABLE_interface_trans' not in cmd_body:
        logger.error('TABLE_interface_trans not found in body\n%s', cmd_body)
        return
    ti = cmd_body['TABLE_interface_trans']

    if 'ROW_interface_trans' not in ti:
        logger.error('ROW_interface_trans not found in body\n%s', cmd_body)
        return

    for ri in ti['ROW_interface_trans']:
        if 'interface_sfp' not in ri:
            logger.error('interface not found in cmd_body\n%s', cmd_body)
            continue

        interface = ri['interface_sfp']
        logger.debug('Found %s in %s', interface, switch_ip)

        if 'fc' not in interface:
            if 'channel' not in interface:
                logger.debug('Skipping %s on %s', interface, switch_ip)
                continue
        else:
            intf_list = interface.split('/')
            port_id = intf_list[1]
            if len(port_id) == 1:
                port_id = '0' + port_id
                interface = intf_list[0] + '/' + port_id

        if interface not in port_dict:
            port_dict[interface] = {}
        per_port_dict = port_dict[interface]

        if 'meta' not in per_port_dict:
            per_port_dict['meta'] = {}
        meta_dict = per_port_dict['meta']

        if 'data' not in per_port_dict:
            per_port_dict['data'] = {}
        data_dict = per_port_dict['data']

        if 'TABLE_calib' not in ri:
            logger.warning('TABLE_calib not found:%s in %s',
                           interface, switch_ip)
            continue
        if 'ROW_calib' not in ri['TABLE_calib']:
            logger.warning('ROW_calib not found:%s in %s',
                           interface, switch_ip)
            continue

        if isinstance(ri['TABLE_calib']['ROW_calib'], dict):
            ri['TABLE_calib']['ROW_calib'] = [ri['TABLE_calib']['ROW_calib']]

        r_calib = ri['TABLE_calib']['ROW_calib'][0]

        if 'sfp' not in r_calib:
            logger.warning('sfp not found:%s in %s',
                           interface, switch_ip)
            continue

        if 'not' in r_calib['sfp']:
            logger.debug('%s in %s in %s', r_calib['sfp'],
                         interface, switch_ip)
            continue

        if 'name' in r_calib:
            meta_dict['sfp_name'] = (str(r_calib['name'])).strip()

        if 'cisco_product_id' in r_calib:
            meta_dict['sfp_pid'] = (str(r_calib['cisco_product_id'])).strip()


        if 'TABLE_calibration' not in r_calib:
            logger.warning('TABLE_calibration not found:%s in %s',
                           interface, switch_ip)
            continue

        if 'ROW_calibration' not in r_calib['TABLE_calibration']:
            logger.warning('ROW_calibration not found:%s in %s',
                           interface, switch_ip)
            continue

        if isinstance(r_calib['TABLE_calibration']['ROW_calibration'], dict):
            r_calib['TABLE_calibration']['ROW_calibration'] = \
                            [r_calib['TABLE_calibration']['ROW_calibration']]

        if 'TABLE_detail' not in \
                    r_calib['TABLE_calibration']['ROW_calibration'][0]:
            logger.warning('TABLE_detail not found:%s in %s',
                           interface, switch_ip)
            continue

        if 'ROW_detail' not in \
        r_calib['TABLE_calibration']['ROW_calibration'][0]['TABLE_detail']:
            logger.warning('ROW_detail not found:%s in %s',
                           interface, switch_ip)
            continue

        rd_temp = r_calib['TABLE_calibration']['ROW_calibration'][0] \
                    ['TABLE_detail']['ROW_detail']

        if isinstance(rd_temp, dict):
            rd_temp = [rd_temp]

        rd = rd_temp[0]

        if 'temperature' in rd:
            data_dict['sfp_temperature'] = \
                        get_float_from_string(rd['temperature'])

        if 'voltage' in rd:
            data_dict['sfp_voltage'] = \
                        get_float_from_string(rd['voltage'])

        if 'current' in rd:
            data_dict['sfp_current'] = \
                        get_float_from_string(rd['current'])

        if 'tx_pwr' in rd:
            data_dict['sfp_tx_pwr'] = \
                        get_float_from_string(rd['tx_pwr'])

        if 'rx_pwr' in rd:
            data_dict['sfp_rx_pwr'] = \
                        get_float_from_string(rd['rx_pwr'])

        if 'tx_faults' in rd:
            data_dict['sfp_tx_faults'] = rd['tx_faults']

        if 'xmit_faults' in rd:
            data_dict['sfp_tx_faults'] = rd['xmit_faults']

    logger.info('Done: parse_sh_int_trans_json for %s', switch_ip)

def parse_sh_int_trans(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface transceiver detail
    """
    if user_args['cli_json']:
        parse_sh_int_trans_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_int_trans for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']

    # Use ? for non-greedy match
    sfp_present_list = re.findall(r'fc.*?Note', cmd_body,  re.DOTALL)
    # Do not use re.DOTALL for single line match
    #sfp_not_present_list = re.findall(r'fc.*?not present', cmd_body)

    for intf in sfp_present_list:
        interface = ''.join(re.findall(r'(fc.*) sfp is', intf))
        intf_list = interface.split('/')
        if len(intf_list) < 2:
            logger.error('Unable to parse:%s', intf)
            continue
        port_id = intf_list[1]
        if len(port_id) == 1:
            port_id = '0' + port_id
            interface = intf_list[0] + '/' + port_id

        logger.debug('Filling %s-', interface)
        if interface not in port_dict:
            port_dict[interface] = {}
        per_port_dict = port_dict[interface]

        if 'data' not in per_port_dict:
            per_port_dict['data'] = {}
        data_dict = per_port_dict['data']

        if 'meta' not in per_port_dict:
            per_port_dict['meta'] = {}
        meta_dict = per_port_dict['meta']

        sfp_name = ''.join(re.findall(r'Name is (\b\S+\b)', intf))
        if sfp_name != '':
            meta_dict['sfp_name'] = sfp_name

        sfp_pid = ''.join(re.findall(r'Cisco pid is (\b\S+\b)', intf))
        if sfp_pid != '':
            meta_dict['sfp_pid'] = sfp_pid

        sfp_temperature = ''.join(re.findall(r'Temperature[ ]{1,}(\b\S+\b)', \
                                             intf))
        if sfp_temperature != '':
            data_dict['sfp_temperature'] = sfp_temperature

        sfp_voltage = ''.join(re.findall(r'Voltage[ ]{1,}(\b\S+\b)', intf))
        if sfp_voltage != '':
            data_dict['sfp_voltage'] = sfp_voltage

        sfp_current = ''.join(re.findall(r'Current[ ]{1,}(\b\S+\b)', intf))
        if sfp_current != '':
            data_dict['sfp_current'] = sfp_current

        sfp_tx_pwr = ''.join(re.findall(r'Tx Power[ ]{1,}(.*?\b\S+\b)', intf))
        if sfp_tx_pwr != '':
            if 'N/A' not in sfp_tx_pwr:
                data_dict['sfp_tx_pwr'] = sfp_tx_pwr

        sfp_rx_pwr = ''.join(re.findall(r'Rx Power[ ]{1,}(.*?\b\S+\b)', intf))
        if sfp_rx_pwr != '':
            if 'N/A' not in sfp_rx_pwr:
                data_dict['sfp_rx_pwr'] = sfp_rx_pwr

        sfp_tx_faults = ''.join(re.findall(r'Transmit Fault Count = (\d+)', \
                                           intf))
        if sfp_tx_faults != '':
            data_dict['sfp_tx_faults'] = sfp_tx_faults

    logger.info('Done: parse_sh_int_trans for %s', switch_ip)

def parse_sh_int_json(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface
    """
    logger.info('parse_sh_int_json for %s', switch_ip)
    prev_interface = None

    port_dict = per_switch_stats_dict['ports']
    if 'sys_ver' not in per_switch_stats_dict:
        logger.warning('sys_ver not found for %s', switch_ip)
    else:
        logger.info('NX-OS version for %s: %s', switch_ip,
                                             per_switch_stats_dict['sys_ver'])

    if 'TABLE_interface' not in cmd_body:
        logger.error('TABLE_interface not found in cmd_body:%s', switch_ip)
        return

    if isinstance(cmd_body['TABLE_interface'], dict):
        cmd_body['TABLE_interface'] = [cmd_body['TABLE_interface']]

    for ti in cmd_body['TABLE_interface']:
        if 'ROW_interface' not in ti:
            logger.error('ROW_interface not found in cmd_body\n%s', cmd_body)
            continue

        if isinstance(ti['ROW_interface'], dict):
            ti['ROW_interface'] = [ti['ROW_interface']]

        for ri in ti['ROW_interface']:
            if 'interface' not in ri:
                if per_switch_stats_dict['sys_ver'] == '8.4(2)' and \
                    prev_interface is not None:
                    interface = prev_interface
                    logger.warning('Using previous interface: %s', prev_interface)
                else:
                    logger.error('interface not found in ROW_interface')
                    continue
            else:
                interface = ri['interface']

            prev_interface = interface
            logger.debug('Found %s in %s', interface, switch_ip)
            if 'fc' not in interface:
                if 'channel' not in interface:
                    logger.debug('Skipping %s on %s', interface, switch_ip)
                    continue
            else:
                intf_list = interface.split('/')
                port_id = intf_list[1]
                if len(port_id) == 1:
                    port_id = '0' + port_id
                    interface = intf_list[0] + '/' + port_id

            if interface not in port_dict:
                port_dict[interface] = {}
            per_port_dict = port_dict[interface]

            if 'meta' not in per_port_dict:
                per_port_dict['meta'] = {}
            meta_dict = per_port_dict['meta']

            if 'data' not in per_port_dict:
                per_port_dict['data'] = {}
            data_dict = per_port_dict['data']

            if 'port_wwn' in ri:
                data_dict['pwwn'] = ri['port_wwn']

            # Remove " from description to prevent line protocol error
            if 'description' in ri:
                data_dict['description'] = (ri['description']).strip('"')

            if 'total_in_errors' in ri:
                data_dict['rx_error'] = int(ri['total_in_errors'])

            if 'total_out_errors' in ri:
                data_dict['tx_error'] = int(ri['total_out_errors'])

            if 'total_in_discards' in ri:
                data_dict['rx_discard'] = int(ri['total_in_discards'])

            if 'total_out_discards' in ri:
                data_dict['tx_discard'] = int(ri['total_out_discards'])

            if 'rx_b2b_credit' in ri:
                data_dict['rx_b2b_credit_remain'] = int(ri['rx_b2b_credit'])

            if 'tx_b2b_credit' in ri:
                data_dict['tx_b2b_credit_remain'] = int(ri['tx_b2b_credit'])

            if 'oper_speed' in ri:
                data_dict['oper_speed'] = \
                            get_speed_num_from_string(ri['oper_speed'])

            if 'port_mode' in ri:
                if isinstance(ri['port_mode'], list):
                    if len(ri['port_mode']) == 3:
                        meta_dict['oper_mode'] = ri['port_mode'][2]
                        data_dict['description'] = \
                            (ri['port_mode'][0]).strip('"')
                    if len(ri['port_mode']) == 2:
                        data_dict['description'] = \
                            (ri['port_mode'][0]).strip('"')
                else:
                    meta_dict['oper_mode'] = ri['port_mode']

            if 'oper_port_state' in ri:
                meta_dict['oper_state'] = ri['oper_port_state']
                if 'down' not in meta_dict['oper_state']:
                    if 'oper_mode' in ri:
                        meta_dict['oper_mode'] = ri['oper_mode']
                else:
                    if 'port_state' in ri:
                        data_dict['port_down_reason'] = ri['port_state']
                    if 'port_down_reason' in ri:
                        data_dict['port_down_reason'] = ri['port_down_reason']

            if 'bundle_if_index' in ri:
                meta_dict['pc'] = ri['bundle_if_index']
            else:
                if 'fc' in interface:
                    meta_dict['pc'] = 'No'

    logger.info('Done: parse_sh_int_json for %s', switch_ip)

def fill_data_from_sh_int(per_port_dict, intf_body, interface):
    """
    show interface - raw output, not JSON or XML
    """

    if 'data' not in per_port_dict:
        per_port_dict['data'] = {}
    data_dict = per_port_dict['data']

    if 'meta' not in per_port_dict:
        per_port_dict['meta'] = {}
    meta_dict = per_port_dict['meta']

    # non-capturing group using ?:
    oper_state = ''.join(re.findall(r'(?:fc.*|port-channel.*) is (\b\S+\b)',
                                   intf_body))
    if oper_state != '':
        meta_dict['oper_state'] = oper_state

    if 'down' in oper_state:
        port_down_reason = ''.join(re.findall( \
            r'(?:fc.*|port-channel.*) is \b\S+\b \((.*)\)', intf_body))
        if port_down_reason != '':
            data_dict['port_down_reason'] = port_down_reason
    else:
        oper_mode = ''.join(re.findall(r'Port mode is (\b\S+\b)', intf_body))
        if oper_mode != '':
            meta_dict['oper_mode'] = oper_mode

    description = ''.join(re.findall(r'Port description is (.*)',
                                     intf_body))
    if description != '':
        # " in description conflicts
        data_dict['description'] = description.strip('"')

    # Capture num from Speed is 48 Gbps or Operating Speed is 32 Gbps
    # Ignore Admin Speed is auto
    oper_speed = ''.join(re.findall(r'(?<!Admin )Speed is (\d+)', intf_body, \
                                    re.IGNORECASE))
    if oper_speed != '':
        data_dict['oper_speed'] = oper_speed

    vsan = ''.join(re.findall(r'Port vsan is (\d+)', intf_body))
    if vsan != '':
        data_dict['vsan'] = vsan

    last_changed = ''.join(re.findall(r'last changed at (.*)', intf_body))
    if last_changed != '':
        data_dict['last_changed'] = last_changed

    # word boundaries (\b) filled with 1 or more non-space
    pwwn = ''.join(re.findall(r'Port WWN is (\b\S+\b)', intf_body))
    if pwwn != '':
        data_dict['pwwn'] = pwwn

    bundle_if_index = ''.join(re.findall( \
                      r'Belongs to (\b\S+\b)', intf_body, re.IGNORECASE))

    if bundle_if_index == '':
        if 'fc' in interface:
            meta_dict['pc'] = 'No'
    else:
        meta_dict['pc'] = bundle_if_index


    rx_bytes = ''.join(re.findall(r'frames input,(\d+) bytes', intf_body))
    if rx_bytes != '':
        data_dict['rx_bytes'] = rx_bytes

    tx_bytes = ''.join(re.findall(r'frames output,(\d+) bytes', intf_body))
    if tx_bytes != '':
        data_dict['tx_bytes'] = tx_bytes

    if 'VL' in intf_body:
        # Add the values of all the VLs
        tx_b2b_list = (''.join(re.findall( \
                      r'Transmit.*remaining.*:[ ]{1,}(.*)', intf_body))).split(',')
        tx_b2b_credit_to_zero = 0
        for per_vl_tx_b2b in tx_b2b_list:
            tx_b2b_credit_to_zero = tx_b2b_credit_to_zero + int(per_vl_tx_b2b)
        data_dict['tx_b2b_credit_to_zero'] = str(tx_b2b_credit_to_zero)

        rx_b2b_list = (''.join(re.findall( \
                      r'Receive.*remaining.*:[ ]{1,}(.*)', intf_body))).split(',')
        rx_b2b_credit_to_zero = 0
        for per_vl_rx_b2b in rx_b2b_list:
            rx_b2b_credit_to_zero = rx_b2b_credit_to_zero + int(per_vl_rx_b2b)
        data_dict['rx_b2b_credit_to_zero'] = str(rx_b2b_credit_to_zero)
    else:
        rx_b2b_credit_remain = ''.join(re.findall( \
            r'(\d+) receive B2B credit remaining', intf_body))
        if rx_b2b_credit_remain != '':
            data_dict['rx_b2b_credit_remain'] = rx_b2b_credit_remain

        tx_b2b_credit_remain = ''.join(re.findall( \
            r'(\d+) transmit B2B credit remaining', intf_body))
        if tx_b2b_credit_remain != '':
            data_dict['tx_b2b_credit_remain'] = tx_b2b_credit_remain

def parse_sh_int(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface
    """
    if user_args['cli_json']:
        parse_sh_int_json(switch_ip, cmd_body, per_switch_stats_dict)
        return

    logger.info('parse_sh_int for %s', switch_ip)
    port_dict = per_switch_stats_dict['ports']
    if 'sys_ver' not in per_switch_stats_dict:
        logger.warning('Missing sys_ver:%s', switch_ip)

    # Use ? for non-greedy match
    fc_cmd_list = re.findall(r'fc.*?Last clearing', cmd_body,  re.DOTALL)
    pc_cmd_list = re.findall(r'port-channel\d+ is.*?\n\n', cmd_body, re.DOTALL)

    for fc_intf in fc_cmd_list:
        interface = ''.join(re.findall(r'(fc.*) is', fc_intf))
        intf_list = interface.split('/')
        if len(intf_list) < 2:
            logger.error('Unable to parse:%s', fc_intf)
            continue
        port_id = intf_list[1]
        if len(port_id) == 1:
            port_id = '0' + port_id
            interface = intf_list[0] + '/' + port_id

        logger.debug('Filling %s-', interface)
        if interface not in port_dict:
            port_dict[interface] = {}
        per_port_dict = port_dict[interface]

        fill_data_from_sh_int(per_port_dict, fc_intf, interface)

    for pc_intf in pc_cmd_list:
        interface = ''.join(re.findall(r'(port-channel.*) is', pc_intf))
        logger.debug('Filling %s-', interface)
        if interface not in port_dict:
            port_dict[interface] = {}
        per_port_dict = port_dict[interface]

        fill_data_from_sh_int(per_port_dict, pc_intf, interface)

    logger.info('Done: parse_sh_int for %s', switch_ip)

def update_stats_dict(switch_ip, per_switch_raw_api_stats_dict,
                      per_switch_stats_dict, dispatcher):
    """Update stats_dict from the raw incoming stats"""

    logger.info('Start parsing stats for %s', switch_ip)

    for cmd in dispatcher:
        logger.info('Start parsing:%s', cmd)
        if cmd not in per_switch_raw_api_stats_dict:
            logger.error('%s not in per_switch_raw_api_stats_dict for %s',
                         cmd, switch_ip)
            continue
        body = per_switch_raw_api_stats_dict[cmd]
        dispatcher[cmd][0](switch_ip, body, per_switch_stats_dict)


###############################################################################
# END: Parser functions
###############################################################################

###############################################################################
# BEGIN: Connection and Collector functions
###############################################################################

def get_switches():
    """

    Parse the input-file argument to get UCS domain(s)

    The format of the file is expected to carry a list as:
    <IP Address 1>,username,password
    <IP Address 2>,username,password
    Only one entry is expected per line. Line with prefix # is ignored
    Location is specified between []
    Initialize stats_dict

    """
    global switch_dict
    global stats_dict
    global response_time_dict
    location = ''
    input_file = user_args['input_file']
    with open(input_file, 'r') as f:
        for line in f:
            if not line.startswith('#'):
                line = line.strip()
                if line.startswith('['):
                    if not line.endswith(']'):
                        logger.error('Input file %s format error. Line starts' \
                        ' with [ but does not end with ]: %s', \
                        input_file, line)
                        return
                    line = line.replace('[', '')
                    line = line.replace(']', '')
                    line = line.strip()
                    location = line
                    continue

                if location == '':
                    logger.error('Location is mandatory in input file')
                    continue

                switch = line.split(',')
                if len(switch) < 7:
                    logger.warning('Line not in correct input format:'
                    'IP_Address,username,password,protocol,port,verify_ssl'
                    ',timeout')
                    continue
                switch_dict[switch[0]] = [switch[1], switch[2], switch[3],
                                          switch[4], switch[5], switch[6]]
                switch_dscr = switch[7] if len(switch) == 8 else ''
                logger.info('Added %s (%s) to switch dict, location:%s',
                            switch[0], switch_dscr, location)
                stats_dict[switch[0]] = {}
                stats_dict[switch[0]]['location'] = location
                stats_dict[switch[0]]['ports'] = {}
                stats_dict[switch[0]]['modules'] = {}

                raw_api_stats[switch[0]] = {}

                response_time_dict[switch[0]] = []

    if not switch_dict:
        logger.error('Nothing to monitor. Check input file.')

def mds_nxapi_connect(switch_ip, switchuser, switchpassword, protocol, port,
                      verify_ssl, timeout, dispatcher):
    """ Connect to a Cisco MDS switches via NX-API and get the response
    of the commands"""

    global raw_api_stats
    timeout = int(timeout)
    cmd_list = []
    api_type = ''
    for cmd in [*dispatcher]:
        cmd_list.append(cmd)
        api_type = dispatcher[cmd][1]

    api_version = "1.2"
    sid = 'sid'
    chunk = 0
    cmd_str = ' ;'.join(cmd_list)
    url = protocol + '://' + switch_ip + ':' + str(port) + '/ins'
    headers = {"content-type":"application/xml"}
    payload = """<?xml version="1.0"?>
                <ins_api>
                    <version>{0}</version>
                    <type>{1}</type>
                    <chunk>{2}</chunk>
                    <sid>{3}</sid>
                    <input>{4}</input>
                    <output_format>xml</output_format>
                </ins_api>""".format(api_version, api_type, chunk, sid, cmd_str)



    logger.debug('Requesting URL:%s, Payload:%s', url, payload)

    if verify_ssl == 'False':
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.debug('verify_ssl is set to False. Ignoring InsecureRequestWarning')
        verify = False
    else:
        logger.debug('verify_ssl is set to True.')
        verify = True

    response = requests.post(url, data=payload, headers=headers,
                             auth=(switchuser,switchpassword), verify=verify)

    if not response.ok:
        logger.error('NXAPI error from %s:%s:%s', switch_ip, \
            response.status_code, requests.status_codes._codes[response.status_code])
        return None

    if user_args.get('raw_dump'):
        current_log_level = logger.level
        logger.setLevel(logging.DEBUG)
        logger.debug('Prining raw Response\n%s', response.content)
        logger.debug('Printing raw dump - DONE')
        logger.setLevel(current_log_level)

    root = ET.fromstring(response.content)
    outputs = root.findall('outputs')
    if outputs is None:
        logger.error("No outputs in response:%s\n%s", switch_ip, \
                                                      response.content)
        return None
    for child1 in outputs:
        output = child1.find('output')
        if output is None:
            logger.error("No output in response:%s\n%s", switch_ip, \
                                                         response.content)
            continue
        for child2 in child1.findall('output'):
            logger.debug('%s %s %s %s', child2.findtext('msg'), \
                        child2.findtext('code'), child2.findtext('input'), \
                        child2.findtext('body'))

            if child2.find('clierror') is not None:
                logger.error("clierror:%s, msg:%s, code:%s, input:%s", \
                child2.findtext('clierror'), child2.findtext('msg'), \
                child2.findtext('code'), child2.findtext('input'))
                continue

            if child2.find('input') is None:
                logger.error("No input in response:%s\%s", switch_ip, \
                                                           response.content)
                continue
            else:
                cmd = child2.findtext('input')

            if child2.find('msg') is None:
                logger.error("No msg in response:%s\%s", switch_ip, \
                                                           response.content)
                continue
            else:
                if 'uccess' not in child2.findtext('msg'):
                    logger.error("Unexpected msg:%s(%s) for input:%s from %s",\
                        child2.findtext('msg'), child2.findtext('code'), \
                        child2.findtext('input'), switch_ip)

            if child2.find('body') is None:
                logger.error("No body in response:%s\%s", switch_ip, \
                                                          response.content)
                continue
            else:
                body =  child2.findtext('body')

            raw_api_stats[switch_ip][cmd] = {}
            raw_api_stats[switch_ip][cmd] = body

    '''
    api_version = 1.2
    jsonrpc_ver = "2.0"
    payload_list = []
    cmd_id = 1
    for cmd in cmd_list:
        api_method = dispatcher[cmd][1]
        payload = dict(jsonrpc = jsonrpc_ver,
                       method = api_method,
                       params = dict(cmd = cmd, version = api_version),
                       id = cmd_id)

        payload_list.append(payload)
        cmd_id = cmd_id + 1

    headers = {"content-type":"application/json-rpc"}
    url = protocol + '://' + switch_ip + ':' + str(port) + '/ins'

    logger.debug('Requesting URL:%s, Payload:%s', url, payload_list)

    if verify_ssl == 'False':
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.debug('verify_ssl is set to False. Ignoring InsecureRequestWarning')
        verify = False
    else:
        logger.debug('verify_ssl is set to True.')
        verify = True


    response = requests.post(url, data=json.dumps(payload_list), headers=headers,
                             auth=(switchuser,switchpassword), verify=verify)

    if not response.ok:
        logger.error('NXAPI error from %s:%s:%s', switch_ip, \
            response.status_code, requests.status_codes._codes[response.status_code])
        return None

    response = response.json()

    if user_args.get('raw_dump'):
        current_log_level = logger.level
        logger.setLevel(logging.DEBUG)
        logger.debug('Prining raw Response\n%s', json.dumps(response, indent=2))
        logger.debug('Printing raw dump - DONE')
        logger.setLevel(current_log_level)

    if isinstance(response, dict):
        response = [response]

    for item in response:
        if "cmd" not in item:
            logger.error("No cmd in response for %s\n%s", switch_ip, item)
            continue
        if "error" in item:
            logger.error('Error from %s for %s\n%s', switch_ip, item["cmd"], item)
            continue
        if "result" not in item:
            logger.error("No result in response for %s\n%s", switch_ip, item)
            continue
        if api_method == 'cli':
            if "body" not in item["result"]:
                logger.error("No body in response for %s\n%s", switch_ip, item)
                continue
            raw_api_stats[switch_ip][item["cmd"]] = {}
            raw_api_stats[switch_ip][item["cmd"]] = item["result"]["body"]
        elif api_method == 'cli_ascii':
            if "msg" not in item["result"]:
                logger.error("No msg in response for %s\n%s", switch_ip, item)
                continue
            raw_api_stats[switch_ip][item["cmd"]] = {}
            raw_api_stats[switch_ip][item["cmd"]] = item["result"]["msg"]
        else:
            logger.error('Unknown api_method:%s, %s', switch_ip, payload_list)

    '''
    return response

def connect_and_pull_stats(executor):
    """
    Wrapper to connect to switches and pull stats

    Must be multithreading aware.

    """

    global switch_dict
    global raw_api_stats
    global stats_dict
    global response_time_dict

    switch_ip = executor[0]
    dispatcher = executor[1]
    idx = executor[2]

    nxapi_start = time.time()
    logger.info('Pull stats from %s for (idx:%s)%s', switch_ip, str(idx),
                                                     [*dispatcher])

    response = mds_nxapi_connect(switch_ip,
                                 switch_dict[switch_ip][0],
                                 switch_dict[switch_ip][1],
                                 switch_dict[switch_ip][2],
                                 switch_dict[switch_ip][3],
                                 switch_dict[switch_ip][4],
                                 switch_dict[switch_ip][5],
                                 dispatcher)

    nxapi_rsp = time.time()
    if response:
        logger.info('Received from %s for %s', switch_ip, [*dispatcher])

        update_stats_dict(switch_ip, raw_api_stats[switch_ip],
                      stats_dict[switch_ip], dispatcher)

    nxapi_parse = time.time()

    response_time = dict(nxapi_start = nxapi_start,
                         nxapi_rsp = nxapi_rsp,
                         nxapi_parse = nxapi_parse)

    response_time_dict[switch_ip].insert(idx, response_time)


def get_switch_stats():
    """
    Connect to switches and pull stats
    Must be multithreading aware.

    """

    global switch_dict

    if len(switch_dict) == 0:
        logger.error('Nothing to connect')
        return

    executor_list = []
    for switch_ip, switch_details in switch_dict.items():
        logger.info('Connect (1) and pull stats from:%s', switch_ip)
        idx = 0
        for dispatch in fn_dispatcher_1:
            list_to_add = []
            list_to_add.append(switch_ip)
            list_to_add.append(dispatch)
            list_to_add.append(idx)
            idx = idx + 1
            executor_list.append(list_to_add)

    logger.debug('Connect and pull stats: executor_list : %s', executor_list)

    future_rsp_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(executor_list)) \
    as e:
        for executor in executor_list:
            future_rsp = e.submit(connect_and_pull_stats, executor)
            future_rsp_list.append(future_rsp)
        for future in concurrent.futures.as_completed(future_rsp_list):
            try:
                rsp = future.result()
                logger.info('Response received as completed:%s', rsp)
            except Exception as excp:
                logger.exception('Exception: %s', excp)

    '''
    for executor in executor_list:
        connect_and_pull_stats(executor)
    '''

    fn_dispatcher_2_intf_str = []
    dispatcher = fn_dispatcher_2
    global intf_fc_str
    global intf_pc_str
    logger.info('Prebuilt FC interface string:%s', intf_fc_str)
    logger.info('Prebuilt port-channel interface string:%s', intf_pc_str)

    count_det_fc = 'show interface ' + intf_fc_str + ' counters detailed'
    count_det_val = [parse_sh_int_counters, 'cli_show_ascii']
    count_det_dict = {count_det_fc:count_det_val}
    if intf_pc_str != '':
        count_det_pc = 'show interface ' + intf_pc_str + ' counters detailed'
        count_det_dict[count_det_pc] = count_det_val
    fn_dispatcher_2_intf_str.append(count_det_dict)

    trans_det_val = [parse_sh_int_trans, 'cli_show_ascii']
    trans_det_fc = 'show interface ' + intf_fc_str + ' transceiver details'
    trans_det_dict = {trans_det_fc:trans_det_val}
    fn_dispatcher_2_intf_str.append(trans_det_dict)

    sh_int_val = [parse_sh_int, 'cli_show_ascii']
    sh_int_fc = 'show interface ' + intf_fc_str
    sh_int_dict = {sh_int_fc:sh_int_val}
    if intf_pc_str != '':
        sh_int_pc = 'show interface ' + intf_pc_str
        sh_int_dict[sh_int_pc] = sh_int_val
    fn_dispatcher_2_intf_str.append(sh_int_dict)


    '''
    if user_args['cli_json']:
        count_det_fc = 'show interface counters detailed'
        count_det_val = [parse_sh_int_counters, 'cli']
        count_det_dict = {count_det_fc:count_det_val}
        fn_dispatcher_2_intf_str.append(count_det_dict)
    else:
        count_det_fc = 'show interface ' + intf_fc_str + ' counters detailed'
        count_det_val = [parse_sh_int_counters, 'cli_ascii']
        count_det_dict = {count_det_fc:count_det_val}
        if intf_pc_str != '':
            count_det_pc = 'show interface ' + intf_pc_str + ' counters detailed'
            count_det_dict[count_det_pc] = count_det_val
        fn_dispatcher_2_intf_str.append(count_det_dict)

    if user_args['cli_json']:
        trans_det_val = [parse_sh_int_trans, 'cli']
    else:
        trans_det_val = [parse_sh_int_trans, 'cli_ascii']
    trans_det_fc = 'show interface ' + intf_fc_str + ' transceiver details'
    trans_det_dict = {trans_det_fc:trans_det_val}
    fn_dispatcher_2_intf_str.append(trans_det_dict)

    if user_args['cli_json']:
        sh_int_val = [parse_sh_int, 'cli']
    else:
        sh_int_val = [parse_sh_int, 'cli_ascii']
    sh_int_fc = 'show interface ' + intf_fc_str
    sh_int_dict = {sh_int_fc:sh_int_val}
    if intf_pc_str != '':
        sh_int_pc = 'show interface ' + intf_pc_str
        sh_int_dict[sh_int_pc] = sh_int_val
    fn_dispatcher_2_intf_str.append(sh_int_dict)
    '''

    dispatcher = fn_dispatcher_2_intf_str
    logger.debug('Dispatcher with intf str:%s', fn_dispatcher_2_intf_str)

    executor_list = []
    for switch_ip, switch_details in switch_dict.items():
        logger.info('Connect (2) and pull stats from:%s', switch_ip)
        # Carry the value of idx from fn_dispatcher_1
        for dispatch in dispatcher:
            list_to_add = []
            list_to_add.append(switch_ip)
            list_to_add.append(dispatch)
            list_to_add.append(idx)
            idx = idx + 1
            executor_list.append(list_to_add)

    logger.debug('Connect and pull stats: executor_list : %s', executor_list)

    future_rsp_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(executor_list)) \
    as e:
        for executor in executor_list:
            future_rsp = e.submit(connect_and_pull_stats, executor)
            future_rsp_list.append(future_rsp)
        for future in concurrent.futures.as_completed(future_rsp_list):
            try:
                rsp = future.result()
                logger.info('Response received as completed:%s', rsp)
            except Exception as excp:
                logger.exception('Exception: %s', excp)

    '''
    for executor in executor_list:
        connect_and_pull_stats(executor)
    '''


###############################################################################
# END: Connection and Collector functions
###############################################################################

# For 'content-type':'application/json-rpc':
#   "method": "cli_ascii" gets raw output
#   "method": "cli" gets data in JSON format
# For 'content-type':'application/xml':
#   <type>cli_show_ascii</type> gets raw output
#   <type>cli_show</type> gets data in XML format
fn_dispatcher_1 = [
    {
        "show version": [parse_sh_ver, 'cli_show_ascii'],
        "show system resources": [parse_sh_sys_resources, 'cli_show_ascii'],
        "show system uptime": [parse_sh_sys_uptime, 'cli_show_ascii'],
        "show module": [parse_sh_mod, 'cli_show_ascii']
    },
    {
        "show port-channel usage": [parse_sh_portc_u, 'cli_show_ascii']
    }
]

fn_dispatcher_2 = [
    {
        "show interface counters detailed": [parse_sh_int_counters, 'cli_show_ascii']
    },
    {
        "show interface transceiver details": [parse_sh_int_trans, 'cli_show_ascii']
    },
    {
        "show interface": [parse_sh_int, 'cli_show_ascii']
    }
]

#        "show fcs ie": parse_sh_fcs_ie

def main(argv):
    """The beginning of the beginning"""

    # Initial tasks
    start_time = time.time()
    if not pre_checks_passed(argv):
        return
    parse_cmdline_arguments()
    setup_logging()

    logger.warning('---------- START (version %s) (last update %s)----------', \
                     __version__, __updated__)

    # Read input file to get the switches
    get_switches()
    input_read_time = time.time()

    # Connect and pull stats
    try:
        get_switch_stats()
    except Exception as excp:
        logger.error('Exception with get_switch_stats:%s', str(excp))
    connect_time = time.time()

    # Print the stats as per the desired output format
    try:
        for switch_ip, switch_details in switch_dict.items():
            stats_dict[switch_ip]['response_time'] = \
                        round((connect_time - input_read_time), 3)
            print_output(switch_ip, stats_dict[switch_ip])
    except Exception as excp:
        logger.exception('Exception with print_output:%s', (str)(excp))

    output_time = time.time()

    # Final tasks

    # Print response time - total and per command set
    time_output = ''
    idx = 0
    for switch_ip, rsp_list in response_time_dict.items():
        time_output = time_output + '\n' \
            '    |------------------------------------------------|\n' \
            '    |     Response time from - {:<15}       |\n' \
            '    |------------------------------------------------|'. \
            format(switch_ip)
        while idx < len(rsp_list):
            if rsp_list[idx]['nxapi_rsp'] > rsp_list[idx]['nxapi_start']:
                nxapi_rsp_time = str(round((rsp_list[idx]['nxapi_rsp'] - \
                                              rsp_list[idx]['nxapi_start']), 2))
            else:
                nxapi_rsp_time = 'N/A'

            if rsp_list[idx]['nxapi_parse'] > rsp_list[idx]['nxapi_rsp']:
                parse_time = str(round((rsp_list[idx]['nxapi_parse'] - \
                                              rsp_list[idx]['nxapi_rsp']), 2))
            else:
                parse_time = 'N/A'

            if rsp_list[idx]['nxapi_parse'] > rsp_list[idx]['nxapi_start']:
                total_time = str(round((rsp_list[idx]['nxapi_parse'] - \
                                              rsp_list[idx]['nxapi_start']), 2))
            else:
                total_time = 'N/A'

            #cmd_str = '\n'.join([*fn_dispatcher[idx]])
            cmd_str = ''
            if idx < len(fn_dispatcher_1):
                for cmd in [*fn_dispatcher_1[idx]]:
                    cmd_str = cmd_str + '\n' + \
                    '    |     {:<40}   |'.format(cmd)
            else:
                idx_2 = idx - len(fn_dispatcher_1)
                for cmd in [*fn_dispatcher_2[idx_2]]:
                    cmd_str = cmd_str + '\n' + \
                    '    |     {:<40}   |'.format(cmd)

            time_output = time_output + '\n' + \
                '    | Command set:{:<2}                                 |'.\
                format(idx + 1)

            time_output = time_output + cmd_str

            time_output = time_output + '\n' + \
            '    |------------------------------------------------|\n'\
            '    | NXAPI Response:{:>8} s | Parsing:{:>8} s |\n'\
            '    |------------------------------------------------|'.\
            format(nxapi_rsp_time, parse_time)

            idx = idx + 1

    time_output = time_output + '\n' \
                   '    |------------------------------------------------|\n'\
                   '    |            Time taken to complete              |\n'\
                   '    |------------------------------------------------|\n'\
                   '    |                               Input:{:7.3f} s  |\n'\
                   '    |       Connect, pull and parse stats:{:7.3f} s  |\n'\
                   '    |                              Output:{:7.3f} s  |\n'\
                   '    |----------------------------------------------  |\n'\
                   '    |                               Total:{:7.3f} s  |\n'\
                   '    |------------------------------------------------|'.\
                   format((input_read_time - start_time),
                          (connect_time - input_read_time),
                          (output_time - connect_time),
                          (output_time - start_time))

    logger.setLevel(logging.INFO)
    logger.info('%s', time_output)
    # DONE: Print response time - total and per command set

    logger.warning('---------- END ----------')

if __name__ == '__main__':
    main(sys.argv)

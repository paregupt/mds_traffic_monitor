#! /usr/bin/python3
"""Pull stats from Cisco MDS 9000 switches and print output in the
desired output format"""

__author__ = "Paresh Gupta"
__version__ = "0.03"

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

    if 'chassis_id' in per_switch_stats_dict:
        switch_fields = switch_fields + ' chassis_id="' + \
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

    if 'response_time' in per_switch_stats_dict:
        switch_fields = switch_fields + ',response_time=' + \
                        str(per_switch_stats_dict['response_time'])

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
            port_tags = port_tags + ',' + key + '=' + str(val)

        port_tags = port_tags + ',switch=' + switch_ip + \
                    ',switchport=' + port

        for key, val in sorted((per_port_dict['data']).items()):
            sep = ' ' if port_fields == '' else ','
            if key == 'description' or key == 'pwwn':
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


def parse_sh_ver(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show version
    """
    logger.info('parse_sh_ver for %s', switch_ip)

    per_switch_stats_dict['sys_ver'] = cmd_body.get('sys_ver_str')
    per_switch_stats_dict['chassis_id'] = cmd_body.get('chassis_id')
    per_switch_stats_dict['switchname'] = cmd_body.get('host_name')
    uptime_secs = cmd_body.get('kern_uptm_secs') + \
                  cmd_body.get('kern_uptm_mins') * SECONDS_IN_MINUTE + \
                  cmd_body.get('kern_uptm_hrs') * MINUTES_IN_HOUR * \
                                                  SECONDS_IN_MINUTE + \
                  cmd_body.get('kern_uptm_days') * HOURS_IN_DAY * \
                                                   MINUTES_IN_HOUR * \
                                                   SECONDS_IN_MINUTE
    per_switch_stats_dict['uptime'] = uptime_secs

    logger.info('Done: parse_sh_ver for %s', switch_ip)

def parse_sh_fcs_ie(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show fcs ie
    """

    logger.info('parse_sh_fcs_ie for %s', switch_ip)

    logger.info('Done: parse_sh_fcs_ie for %s', switch_ip)

def parse_sh_sys_resources(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show system resources
    """
    logger.info('parse_sh_fcs_ie for %s', switch_ip)

    per_switch_stats_dict['cpu_user'] = cmd_body.get('cpu_state_user')
    per_switch_stats_dict['cpu_kernel'] = cmd_body.get('cpu_state_kernel')
    per_switch_stats_dict['mem_total'] = cmd_body.get('memory_usage_total')
    per_switch_stats_dict['mem_used'] = cmd_body.get('memory_usage_used')
    per_switch_stats_dict['load_avg_1min'] = cmd_body.get('load_avg_1min')

    logger.info('Done: parse_sh_fcs_ie for %s', switch_ip)

def parse_sh_sys_uptime(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show system uptime
    """
    logger.info('parse_sh_sys_uptime for %s', switch_ip)

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

    logger.info('Done: parse_sh_sys_uptime for %s', switch_ip)

def parse_sh_int_counters(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface counters detail
    """
    logger.info('parse_sh_int_counters for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']
    #TODO: Watch out for this check if show version finishes later
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

                        if 'tx_b2b_credit_to_zero' in rcon:
                            data_dict['tx_b2b_credit_to_zero'] = \
                                                    rcon['tx_b2b_credit_to_zero']
            else:
                logger.error('Unable to decode body:%s in %s',
                             interface, cmd_body)
                continue

    logger.info('Done: parse_sh_int_counters for %s', switch_ip)

def parse_sh_int_trans(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface transceiver detail
    """
    logger.info('parse_sh_int_trans for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']
    #TODO: Watch out for this check if show version finishes later
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

    logger.info('Done: parse_sh_int_trans for %s', switch_ip)

def parse_sh_int(switch_ip, cmd_body, per_switch_stats_dict):
    """
    show interface
    """
    logger.info('parse_sh_int for %s', switch_ip)

    port_dict = per_switch_stats_dict['ports']
    #TODO: Watch out for this check if show version finishes later
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
                logger.error('interface not found in ROW_interface')
                continue

            interface = ri['interface']
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

            if 'oper_port_state' in ri:
                meta_dict['oper_state'] = ri['oper_port_state']
                if 'down' not in meta_dict['oper_state']:
                    if 'oper_mode' in ri:
                        meta_dict['oper_mode'] = ri['oper_mode']

                    if 'port_mode' in ri:
                        if isinstance(ri['port_mode'], list):
                            if len(ri['port_mode']) == 3:
                                meta_dict['oper_mode'] = ri['port_mode'][2]
                                data_dict['description'] = \
                                    (ri['port_mode'][0]).strip('"')
                        else:
                            meta_dict['oper_mode'] = ri['port_mode']

            if 'bundle_if_index' in ri:
                meta_dict['pc'] = ri['bundle_if_index']
            else:
                if 'fc' in interface:
                    meta_dict['pc'] = 'No'

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
        dispatcher[cmd](switch_ip, body, per_switch_stats_dict)


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

                raw_api_stats[switch[0]] = {}

                response_time_dict[switch[0]] = []

    if not switch_dict:
        logger.error('Nothing to monitor. Check input file.')

def mds_nxapi_connect(switch_ip, switchuser, switchpassword, protocol, port,
                      verify_ssl, timeout, cmd_list):
    """ Connect to a Cisco MDS switches via NX-API and get the response
    of the commands in cmd_str"""

    timeout = int(timeout)
    api_method = "cli"
    api_version = 1.2
    jsonrpc_ver = "2.0"
    payload_list = []
    cmd_id = 1
    for cmd in cmd_list:
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
                             auth=(switchuser,switchpassword), verify=verify).json()

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
                                 [*dispatcher])

    nxapi_rsp = time.time()
    logger.info('Received from %s for %s', switch_ip, [*dispatcher])

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
        if "body" not in item["result"]:
            logger.error("No body in response for %s\n%s", switch_ip, item)
            continue
        raw_api_stats[switch_ip][item["cmd"]] = {}
        raw_api_stats[switch_ip][item["cmd"]] = item["result"]["body"]

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
        logger.info('Connect and pull stats from:%s', switch_ip)
        idx = 0
        for dispatch in fn_dispatcher:
            list_to_add = []
            list_to_add.append(switch_ip)
            list_to_add.append(dispatch)
            list_to_add.append(idx)
            idx = idx + 1
            executor_list.append(list_to_add)

    logger.debug('Connect and pull stats: executor_list : %s', executor_list)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(executor_list)) as e:
        for executor in executor_list:
            e.submit(connect_and_pull_stats, executor)
    '''
    for executor in executor_list:
        connect_and_pull_stats(executor)
    '''

###############################################################################
# END: Connection and Collector functions
###############################################################################

fn_dispatcher = [
    {
        "show version": parse_sh_ver,
        "show system resources": parse_sh_sys_resources,
        "show system uptime": parse_sh_sys_uptime
    },
    {
        "show interface counters detailed": parse_sh_int_counters
    },
    {
        "show interface transceiver details": parse_sh_int_trans
    },
    {
        "show interface": parse_sh_int
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

    logger.warning('---------- START (version %s)----------', __version__)

    # Read input file to get the switches
    get_switches()
    input_read_time = time.time()

    # Connect and pull stats
    try:
        get_switch_stats()
    except Exception as e:
        logger.exception('Exception with get_switch_stats')
    connect_time = time.time()

    # Print the stats as per the desired output format
    try:
        for switch_ip, switch_details in switch_dict.items():
            stats_dict[switch_ip]['response_time'] = \
                        round((connect_time - input_read_time), 3)
            print_output(switch_ip, stats_dict[switch_ip])
    except Exception as e:
        logger.exception('Exception with print_output:%s', (str)(e))

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
            for cmd in [*fn_dispatcher[idx]]:
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

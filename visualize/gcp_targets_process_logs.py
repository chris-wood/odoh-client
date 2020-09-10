import json
import pandas
import numpy

import matplotlib.pyplot as plt
from collections import defaultdict


def percentile(data_row, percentile_value=95):
    return numpy.percentile(data_row, percentile_value)


def cdf(data):
    n = len(data)
    x = numpy.sort(data)
    y = numpy.arange(1, n + 1) / n
    return x, y


def read_gcp_target_logs(filedir='logs', filename='log-2020-07-31-2216.json'):
    filepath = filedir + "/" + filename
    f = open(filepath)
    json_data = json.load(f)
    return json_data


def flatten_target_logs(data):
    """
    Flattens the JSON parsed data into the following data frame

    [LogType, TargetName, ExperimentID, ProtocolType, Key, Resolver, Start, TargetQueryDecryptionTime,
     TargetQueryResolutionTime, TargetAnswerEncryptionTime, EndTime, Status]
    :param data:
    :return:
    """
    rows = []
    gcp_target_log_name = "odohserver-gcp"
    rust_target_log_name = "odoh-ingestion"
    for item in data:
        log_name = item['logName']
        is_target_log = False
        if gcp_target_log_name in log_name or rust_target_log_name in log_name:
            is_target_log = True
        if is_target_log:
            payload = json.loads(item['textPayload'])
            timestamp = payload['Timestamp']
            resolver_chosen = payload['Resolver']
            start = timestamp['Start']
            target_query_decryption_time = timestamp['TargetQueryDecryptionTime']
            target_query_resolution_time = timestamp['TargetQueryResolutionTime']
            target_answer_encryption_time = timestamp['TargetAnswerEncryptionTime']
            end_time = timestamp['EndTime']
            status = payload['Status']
            target_name = payload['IngestedFrom']
            experiment_id = payload['ExperimentID']
            protocol_type = payload['ProtocolType']
            key = payload['RequestID']
            row = [target_name, target_name, experiment_id, protocol_type, key, resolver_chosen,
                   start, target_query_decryption_time, target_query_resolution_time, target_answer_encryption_time,
                   end_time, status]
            rows.append(row)
    headers = ['LogType', 'TargetName', 'ExperimentID', 'ProtocolType', 'Key', 'Resolver',
               'Start', 'TargetQueryDecryptionTime', 'TargetQueryResolutionTime', 'TargetAnswerEncryptionTime',
               'EndTime', 'Status']

    df = pandas.DataFrame(data=rows, columns=headers)
    df.to_csv('logs/target_logs_dataframe.csv', header=True, index=False)
    return df


def plot_resolver_specific_timings_as_cdf(network_performance, with_failures):
    # CDF for resolver times
    fig, ax = plt.subplots(nrows=1, ncols=1)
    for key, value in network_performance.items():
        X, Y = cdf(value)
        ax.plot(X, Y, label=key)
    ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.set_title('Target Resolver Resolution Time')
    ax.set_xlabel('Time (ms)')
    ax.set_ylabel('CDF')
    # ax.set_xscale('log')
    if with_failures:
        plt.savefig('logs/results/target/all_targets_resolver_timings_with_failures.png', bbox_inches='tight')
    else:
        plt.savefig('logs/results/target/all_targets_resolver_timings.png', bbox_inches='tight')


def plot_target_resolver_choice_timings_as_cdf(target_resolver_pair_performance, with_failures):
    # CDF for resolver times
    fig, ax = plt.subplots(nrows=1, ncols=1)
    all_values = []
    for key, value in target_resolver_pair_performance.items():
        if 'gcp' in key:
            all_values.extend(value)
            key = key.split('-')[1]
            key = key[:len(key) - 3]
            X, Y = cdf(value)
            ax.plot(X, Y, label=key)
    all_values = sorted(all_values)
    X, Y = cdf(all_values)
    ax.plot(X, Y, label='Aggregate', linestyle="-.")
    ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.set_title('Target Resolver Resolution Time')
    ax.set_xlabel('Time (ms)')
    ax.set_xscale('log')
    ax.set_ylabel('CDF')
    if with_failures:
        plt.savefig('logs/results/target/targets_resolver_pair_timings_with_failures.png', bbox_inches='tight')
    else:
        plt.savefig('logs/results/target/targets_resolver_pair_timings.png', bbox_inches='tight')


def plot_target_choice_timings_as_cdf(target_performance, with_failures):
    # CDF for resolver times
    fig, ax = plt.subplots(nrows=1, ncols=1)
    for key, value in target_performance.items():
        X, Y = cdf(value)
        ax.plot(X, Y, label=key)
    ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.set_title('Target Resolver Resolution Time')
    ax.set_xlabel('Time (ms)')
    # ax.set_xscale('log')
    ax.set_ylabel('CDF')
    if with_failures:
        plt.savefig('logs/results/target/targets_timings_with_failures.png', bbox_inches='tight')
    else:
        plt.savefig('logs/results/target/targets_timings.png', bbox_inches='tight')


def find_compute_overhead(successful_queries_filtered, param, with_failures):
    values = successful_queries_filtered[param].to_list()
    fig, ax = plt.subplots(nrows=1, ncols=1)
    X, Y = cdf(values)
    ax.plot(X, Y, label='Compute overhead in {}'.format(param))
    # ax.set_xscale('log')
    ax.legend()
    ax.set_xlabel('Compute Overhead Time (ms)')
    ax.set_ylabel('CDF')
    if with_failures:
        plt.savefig('logs/results/target/aggregate_{}_compute_overhead_with_failures.png'.format(param), bbox_inches='tight')
    else:
        plt.savefig('logs/results/target/aggregate_{}_compute_overhead.png'.format(param), bbox_inches='tight')
    for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
        print("[COMPUTE OVERHEAD] {} [{} Percentile] : {}".format(param, percentile_value, percentile(values, percentile_value)))


def find_compute_overhead_split_by_target(successful_queries_filtered, param, target, with_failures):
    filtered_frame = successful_queries_filtered[successful_queries_filtered['TargetName'] == target]
    values = filtered_frame[param].to_list()
    fig, ax = plt.subplots(nrows=1, ncols=1)
    X, Y = cdf(values)
    ax.plot(X, Y, label='Compute overhead in {}'.format(param))
    ax.legend()
    ax.set_xlabel('Compute Overhead Time (ms)')
    # ax.set_xscale('log')
    ax.set_ylabel('CDF')
    if with_failures:
        plt.savefig('logs/results/target/{}_{}_compute_overhead_with_failures.png'.format(target, param), bbox_inches='tight')
    else:
        plt.savefig('logs/results/target/{}_{}_compute_overhead.png'.format(target, param), bbox_inches='tight')
    for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
        print("[COMPUTE OVERHEAD] {} {} [{} Percentile] : {}".format(target, param, percentile_value, percentile(values, percentile_value)))


def process_dataframe_target_logs(dfpath='logs/target_logs_dataframe.csv', with_failures=False):
    df = pandas.read_csv(dfpath)
    if not with_failures:
        successful_queries_filtered = df[df['Status'] == True]
    else:
        successful_queries_filtered = df
    available_resolvers = list(successful_queries_filtered['Resolver'].value_counts().to_dict().keys())
    successful_queries_filtered['question_decryption'] = \
        numpy.where(successful_queries_filtered['TargetName'].str.contains('gcp'),
                    ((successful_queries_filtered['TargetQueryDecryptionTime'] - successful_queries_filtered['Start']) / (1000.0 * 1000.0)),
                    (successful_queries_filtered['TargetQueryDecryptionTime'] - successful_queries_filtered['Start']))  # for ms
    successful_queries_filtered['resolver_time'] = \
        numpy.where(successful_queries_filtered['TargetName'].str.contains('gcp'),
                    ((successful_queries_filtered['TargetQueryResolutionTime'] - successful_queries_filtered['TargetQueryDecryptionTime']) / (1000.0 * 1000.0)),
                    (successful_queries_filtered['TargetQueryResolutionTime'] - successful_queries_filtered['TargetQueryDecryptionTime']) / (1000.0 * 1000.0))  # for ms
    successful_queries_filtered['answer_encryption'] = \
        numpy.where(successful_queries_filtered['TargetName'].str.contains('gcp'),
                    (successful_queries_filtered['TargetAnswerEncryptionTime'] - successful_queries_filtered['TargetQueryResolutionTime']) / (1000.0 * 1000.0),
                    (successful_queries_filtered['TargetAnswerEncryptionTime'] - successful_queries_filtered['TargetQueryResolutionTime']))  # for ms

    successful_queries_filtered.to_csv('logs/target_intermediate.csv', header=True, index=False)
    network_performance = defaultdict(list)

    for resolver in available_resolvers:
        filtered_data = successful_queries_filtered[successful_queries_filtered['Resolver'] == resolver]
        for filter_type in ['resolver_time']:
            values = sorted(filtered_data[filter_type].to_list())
            network_performance[resolver].extend(values)
            for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
                print("[{}] ==> [{} Percentile] : {}".format(filter_type, percentile_value, percentile(values, percentile_value)))

    plot_resolver_specific_timings_as_cdf(network_performance, with_failures)

    targets = list(successful_queries_filtered['TargetName'].value_counts().to_dict().keys())
    target_resolver_pair_performance = defaultdict(list)
    target_performance = defaultdict(list)
    for target in targets:
        for resolver in available_resolvers:
            key = "{} - {}".format(target, resolver)
            filtered_target_data = successful_queries_filtered[(successful_queries_filtered['TargetName'] == target) &
                                                               (successful_queries_filtered['Resolver'] == resolver)]
            for filter_type in ['resolver_time']:
                values = sorted(filtered_target_data[filter_type].to_list())
                target_resolver_pair_performance[key].extend(values)
                for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
                    print("[{}] for {} ==> [{} Percentile] : {}".format(filter_type, key, percentile_value, percentile(values, percentile_value)))

    for target in targets:
        key = "{}".format(target)
        filtered_target_data = successful_queries_filtered[(successful_queries_filtered['TargetName'] == target)]
        for filter_type in ['resolver_time']:
            values = sorted(filtered_target_data[filter_type].to_list())
            target_performance[key].extend(values)
            for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
                print("[{}] for {} ==> [{} Percentile] : {}".format(filter_type, key, percentile_value, percentile(values, percentile_value)))

    plot_target_resolver_choice_timings_as_cdf(target_resolver_pair_performance, with_failures)
    plot_target_choice_timings_as_cdf(target_performance, with_failures)

    find_compute_overhead(successful_queries_filtered, 'question_decryption', with_failures)
    find_compute_overhead(successful_queries_filtered, 'answer_encryption', with_failures)

    for target in targets:
        find_compute_overhead_split_by_target(successful_queries_filtered, 'question_decryption', target, with_failures)
        find_compute_overhead_split_by_target(successful_queries_filtered, 'answer_encryption', target, with_failures)


if __name__ == '__main__':
    # data = read_gcp_target_logs(filedir='logs/EXP10-ODOH-4G')
    # df = flatten_target_logs(data)
    # print(df.shape)
    process_dataframe_target_logs(dfpath='logs/odoh_target_logs_dataframe.csv')
    # process_dataframe_target_logs(dfpath='logs/odoh_target_logs_dataframe.csv', with_failures=True)

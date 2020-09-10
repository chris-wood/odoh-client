import os

import numpy
import pandas
import matplotlib.pyplot as plt


def read_files(filedir='logs/DNSCRYPT-LOGS'):
    filenames = os.listdir(filedir)
    filenames = [x for x in filenames if x != 'fetch_logs.sh']
    m_df = []
    for filename in filenames:
        df = pandas.read_csv(filedir+'/{}'.format(filename), delimiter='\t', names=['Timestamp', 'Proxy', 'Host', 'DnsType', 'Status', 'Time', 'Target'])
        df = df[df['Status'] == 'PASS']
        df['Client'] = filename.split('-query.log')[0]
        df['timetaken'] = df['Time'].str.replace('ms', '')
        m_df.append(df)
        print("[DONE] {} : ({})".format(filename, df.shape))
    return pandas.concat(m_df)


def percentile(data_row, percentile_value=95):
    return numpy.percentile(data_row, percentile_value)


def cdf(data):
    n = len(data)
    x = numpy.sort(data) # sort your data
    y = numpy.arange(1, n + 1) / n # calculate cumulative probability
    return x, y


def plot_resolution_time(df):
    successful_df = df[df['Status'] == 'PASS']
    times = successful_df['timetaken'].to_list()
    X, Y = cdf(times)
    for p in [50, 60, 70, 75, 80, 85, 90, 95, 99, 99.9]:
        print("[DNSCRYPT] {} Percentile : {}".format(p, percentile(times, p)))
    fig, ax = plt.subplots(nrows=1, ncols=1)
    ax.plot(X, Y, label='DNSCrypt')
    ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.set_title('CDF Of DNSCrypt Response Time')
    ax.set_xlabel('Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_xscale('log')
    plt.savefig('logs/results/dnscrypt_success_cdf.png', bbox_inches='tight')


if __name__ == '__main__':
    # df = read_files()
    # df.to_csv('logs/all_dnscrypt_logs.csv', header=True, index=False)
    df = pandas.read_csv('logs/all_dnscrypt_logs.csv')
    plot_resolution_time(df)

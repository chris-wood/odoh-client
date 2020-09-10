import json
from collections import defaultdict

import numpy
import pandas
import matplotlib.pyplot as plt


def percentile(data_row, percentile_value=95):
    return numpy.percentile(data_row, percentile_value)


def cdf(data):
    n = len(data)
    x = numpy.sort(data) # sort your data
    y = numpy.arange(1, n + 1) / n # calculate cumulative probability
    return x, y


def read_page_load_log(filedir='logs/pageload', filename='firefox-logs-Do53.log'):
    filepath = '{}/{}'.format(filedir, filename)
    lines = [json.loads(line.rstrip()) for line in open(filepath)]
    return lines


def flatten_into_dataframe(data, protocol):
    header = ['Protocol', 'navigationStart', 'redirectStart', 'redirectEnd', 'fetchStart', 'domainLookupStart',
              'domainLookupEnd', 'connectStart', 'secureConnectionStart', 'connectEnd', 'requestStart', 'responseStart',
              'responseEnd', 'domLoading', 'domInteractive', 'domContentLoadedEventStart', 'domContentLoadedEventEnd',
              'domComplete', 'loadEventStart', 'loadEventEnd', 'Hostname']
    data_rows = []
    for row in data:
        data_row = []
        for category in header:
            if category == 'Protocol':
                data_row.append(protocol)
            else:
                data_row.append(row[category])
        data_rows.append(data_row)

    df = pandas.DataFrame(data=data_rows, columns=header)
    df.to_csv('logs/pageload/{}.csv'.format(protocol), header=True, index=False)
    return df


def print_percentile_matrix(protocol_dict):
    selector_pvalues = [50, 60, 70, 75, 80, 85, 90, 95, 99, 99.9]
    print("{} {}".format("////", selector_pvalues))
    results = {}
    for key, value in protocol_dict.items():
        res = []
        for p_value in selector_pvalues:
            res.append(percentile(value, p_value))
        results[key] = res

    compare_keys = [('Do53-1.1.1.1', 'Do53-Comcast'), ('Do53-Comcast', 'DOH'),
                    ('DOH', 'ODOH'), ('Do53-Comcast', 'ODOH'),
                    ('Do53-1.1.1.1', 'ODOH')]
    for orig, newval in compare_keys:
        v1 = results[orig]
        v2 = results[newval]
        percentages = []
        for i in range(0, len(v1)):
            p_val = ((v2[i] - v1[i]) / v1[i]) * 100.0
            percentages.append(p_val)
        print("{} vs {}, {},".format(orig, newval, percentages))


def process_and_build_comparision_per_host(df):
    print(df)
    result_map = defaultdict(list)  # in order [DO53-CF, DO53-CC, DOH, ODOH]
    protocols = ['UW-DOH-Chrome', 'UW-ODOH-Chrome', 'UW-1.1.1.1-Chrome', 'UW-ISP-Chrome', 'UW-ODOH-OP']
    protocol_count = 0
    for protocol in protocols:
        frame = df[df['Protocol'] == protocol]
        if protocol == protocols[-1]:
            print(frame)
        for index, row in frame.iterrows():
            hostname = row['Hostname']
            result_map[hostname].append(row['loadEventEnd'] - row['navigationStart'])  # page load times
        # Check for missing lengths and pad them to 0
        protocol_count += 1
        for k, values in result_map.items():
            if len(values) < protocol_count:
                result_map[k].append(0)

    rows = []
    for key, values in result_map.items():
        row = [key]
        for v in values:
            row.append(v)
        rows.append(row)

    print(rows)
    xdf = pandas.DataFrame(data=rows, columns=['Hostname',
                                               'UW-DOH-Chrome', 'UW-ODOH-Chrome', 'UW-1.1.1.1-Chrome', 'UW-ISP-Chrome',
                                               'UW-ODOH-OP'])
    xdf.to_csv('logs/pageload/aggregate.csv', header=True, index=False)

    fig, ax = plt.subplots(nrows=1, ncols=1)
    uwdohchrome = [x for x in sorted(xdf['UW-DOH-Chrome'].to_list())]
    uwodohchrome = [x for x in sorted(xdf['UW-ODOH-Chrome'].to_list())]
    uwcfchrome = [x for x in sorted(xdf['UW-1.1.1.1-Chrome'].to_list())]
    uwispchrome = [x for x in sorted(xdf['UW-ISP-Chrome'].to_list())]
    uwodohop = [x for x in sorted(xdf['UW-ODOH-OP'].to_list())]

    selector_pvalues = [50, 60, 70, 75, 80, 85, 90, 95, 99, 99.9]
    for p, x in [
        ('UW-DOH-Chrome', uwdohchrome),
        ('UW-ODOH-Chrome', uwodohchrome),
        ('UW-1.1.1.1-Chrome', uwcfchrome),
        ('UW-ISP-Chrome', uwispchrome),
        ('UW-ODOH-OP', uwodohop),
    ]:
        for s in selector_pvalues:
            print("{} @ {} Percentile: {}".format(p, s, percentile(x, s)))

    ax.plot(numpy.arange(len(uwdohchrome)), uwdohchrome, label='UW-DOH-Chrome')
    ax.plot(numpy.arange(len(uwodohchrome)), uwodohchrome, label='UW-ODOH-Chrome')
    ax.plot(numpy.arange(len(uwcfchrome)), uwcfchrome, label='UW-1.1.1.1-Chrome')
    ax.plot(numpy.arange(len(uwispchrome)), uwispchrome, label='UW-ISP-Chrome')
    ax.plot(numpy.arange(len(uwodohop)), uwodohop, label='UW-ODOH-OP')
    ax.set_title('Page load time impact Timeline')
    ax.set_ylabel('Time')
    ax.set_yscale('log')
    ax.set_xlabel('Website #')
    ax.legend()
    plt.savefig('logs/results/pageload/timeline_performance.png', bbox_inches='tight')


def boxplot_page_load_time_impact(protocol_page_load_time_impact):
    result = []
    for protocol, results in protocol_page_load_time_impact.items():
        for value in results:
            result.append([protocol, value])
    df = pandas.DataFrame(data=result, columns=['Protocol', 'PLT'])
    import seaborn as sns
    fig, ax = plt.subplots(nrows=1, ncols=1)
    ax = sns.boxplot(y=df['Protocol'], x=df['PLT'], showfliers = False)
    ax.set_xlabel("Page Load Time (ms)")
    ax.set_ylabel("Protocol Type")
    # ax.set_xscale('log')
    # ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    plt.savefig('logs/results/pageload/plt_impact_boxplot.png', bbox_inches='tight')


def compare_dns_impact_on_page_load():
    uwdohchrome = pandas.read_csv('logs/pageload/UW-DOH-Chrome.csv')
    uwodohchrome = pandas.read_csv('logs/pageload/UW-ODOH-Chrome.csv')
    uwcfchrome = pandas.read_csv('logs/pageload/UW-1.1.1.1-Chrome.csv')
    uwispchrome = pandas.read_csv('logs/pageload/UW-ISP-Chrome.csv')
    uwodohop = pandas.read_csv('logs/pageload/UW-ODOH-OP.csv')

    uwcfchrome = uwcfchrome[uwcfchrome['loadEventEnd'] != 0]
    uwdohchrome = uwdohchrome[uwdohchrome['loadEventEnd'] != 0]
    uwodohchrome = uwodohchrome[uwodohchrome['loadEventEnd'] != 0]
    uwispchrome = uwispchrome[uwispchrome['loadEventEnd'] != 0]
    uwodohop = uwodohop[uwodohop['loadEventEnd'] != 0]

    available_dataframes = [
        (uwcfchrome, 'UW-1.1.1.1-Chrome'),
        (uwispchrome, 'UW-ISP-Chrome'),
        (uwdohchrome, 'UW-DOH-Chrome'),
        (uwodohchrome, 'UW-ODOH-Chrome'),
        (uwodohop, 'UW-ODOH-OP'),
    ]
    cumulativedf = pandas.concat([uwcfchrome, uwispchrome, uwdohchrome, uwodohchrome, uwodohop])
    cumulativedf.to_csv('logs/pageload/uw_aggregate.csv', header=True, index=False)
    fig, ax = plt.subplots(nrows=2, ncols=1, figsize=(9, 9))
    colors = ['red', 'blue', 'magenta', 'black', 'purple', 'magenta', 'maroon', 'yellow']

    left, bottom, width, height = [0.67, 0.15, 0.2, 0.2]
    ax2 = fig.add_axes([left, bottom, width, height])

    PLT_REPLACEMENT = {}
    PLT_REPLACEMENT['UW-1.1.1.1-Chrome'] = 'Do53 Cloudflare DNS'
    PLT_REPLACEMENT['UW-ISP-Chrome'] = 'Do53 ISP DNS'
    PLT_REPLACEMENT['UW-DOH-Chrome'] = 'DOH Cloudflare DNS'
    PLT_REPLACEMENT['UW-ODOH-Chrome'] = 'ODOH (OnPath Proxy)'
    PLT_REPLACEMENT['UW-ODOH-OP'] = 'ODOH (OffPath Proxy)'
    protocol_page_load_time_impact = defaultdict(list)
    for df, protocol in available_dataframes:
        PLTs = []
        DNS = []
        TTFB = []
        for i, row in df.iterrows():
            domainLookupEnd = row['domainLookupEnd']
            domainLookupStart = row['domainLookupStart']
            firstByteStart = row['responseStart']
            responseFetched = row['responseEnd']
            pageLoadEventEnd = row['loadEventEnd']
            navigationStart = row['navigationStart']
            page_load_time = pageLoadEventEnd - navigationStart
            dns_time = domainLookupEnd - domainLookupStart
            ttfb = firstByteStart - navigationStart
            if page_load_time > 0 and dns_time > 0:
                PLTs.append(page_load_time)
                DNS.append(dns_time)
                TTFB.append(ttfb)
        X, Y = cdf(DNS)
        index = len(Y)
        for i, x in enumerate(Y):
            if x <= 0.99:
                index = i
        X = X[:index]
        Y = Y[:index]
        ax[0].plot(X, Y, label='{}'.format(PLT_REPLACEMENT[protocol]))
        # PLTs = PLTs[5:]
        protocol_page_load_time_impact[protocol].extend(PLTs)
        X_O, Y_O = cdf(PLTs)
        index = len(Y)
        for i, x in enumerate(Y):
            if x <= 0.8:
                index = i
        X = X_O[:index]
        Y = Y_O[:index]
        PLTs = PLTs[:index]
        protocol = PLT_REPLACEMENT[protocol]
        ax[1].plot(X, Y, label='{}'.format(protocol), linestyle='-')
        X = X_O[index:]
        Y = Y_O[index:]
        ax2.plot(X, Y, linestyle='-')
        # protocol_page_load_time_impact["{}-{}".format("DNSLookup", protocol)].extend(DNS)
        # protocol_page_load_time_impact["{}-{}".format("TTFB", protocol)].extend(TTFB)
    # ax[0].legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    # ax[0].legend()
    # ax[1].legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax[0].legend(loc='best', bbox_to_anchor=(1.0, 0.5))
    ax[0].set_xscale('log')
    # ax[1].set_xscale('log')
    # ax2.set_xscale('log')
    # ax[0].set_xlabel('Time (ms)')
    ax[1].set_xlabel('Time (ms)')
    ax[0].set_ylabel('CDF')
    ax[1].set_ylabel('CDF')
    ax[0].set_title('[p99] DNS Lookup Time during Page Loads Using different DNS Protocols')
    ax[1].set_title('[p99] Page Load Time Comparisons of Chrome Using different DNS Protocols')
    plt.savefig('logs/results/pageload/{}'.format('compare_dns_lookup_impact.png'), bbox_inches='tight')
    # print_percentile_matrix(protocol_page_load_time_impact)
    boxplot_page_load_time_impact(protocol_page_load_time_impact)

    df = pandas.concat([uwdohchrome, uwodohchrome, uwcfchrome, uwispchrome, uwodohop])
    process_and_build_comparision_per_host(df)


def main():
    filename_protocols = [
                          ('firefox-logs-ODOH-UW-ODOH-NoPath-AD-500.log', 'UW-ODOH-ADBlock'),
                          ('Fresh-logs-ODOH-UW-DOH-Chrome-500.log', 'UW-DOH-Chrome'),
                          ('Fresh-logs-ODOH-UW-1111-Chrome-500.log', 'UW-1.1.1.1-Chrome'),
                          ('Fresh-logs-ODOH-UW-ISP-Chrome-500.log', 'UW-ISP-Chrome'),
                          ('Fresh-logs-ODOH-UW-ODOH-OP-Chrome-500.log', 'UW-ODOH-OP'),
    ]
    for filename, protocol in filename_protocols:
        lines = read_page_load_log(filename=filename)
        df = flatten_into_dataframe(lines, protocol)

    compare_dns_impact_on_page_load()


main()

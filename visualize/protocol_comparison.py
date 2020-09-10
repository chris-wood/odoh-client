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


def plot_protocol_wise_clients_comparision_as_cdf(protocol_network_performance, with_failures):
    fig, ax = plt.subplots(nrows=1, ncols=1)
    for protocol, result in protocol_network_performance.items():
        linestyle_use = '-'
        for key, value in result.items():
            X, Y = cdf(value)
            ax.plot(X, Y, linestyle=linestyle_use, label='{}-{}'.format(protocol, key))
    ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.set_title('Network Response Time Comparision for Vantage Point Clients')
    ax.set_xlabel('Time (ms)')
    ax.set_xscale('log')
    ax.set_ylabel('CDF')
    if with_failures:
        plt.savefig('logs/results/clients_response_times_cdf_compare_with_failures_log.png', bbox_inches='tight')
    else:
        plt.savefig('logs/results/clients_response_times_compare_cdf_log.png', bbox_inches='tight')


def plot_protocol_wise_all_comparision_as_cdf(protocol_network_performance, with_failures):
    fig, ax = plt.subplots(nrows=1, ncols=1)
    left, bottom, width, height = [0.5, 0.3, 0.3, 0.3]
    ax2 = fig.add_axes([left, bottom, width, height])
    protocol_label_replacement = {}
    protocol_label_replacement['ODOH'] = 'Oblivious DNS-over-HTTPS (ODOH)'
    protocol_label_replacement['DOH'] = 'DNS-over-HTTPS (DOH)'
    protocol_label_replacement['pDOH'] = 'Proxied DNS-over-HTTPS (pDOH)'
    protocol_label_replacement['ODOHse'] = 'Clear-Text ODOH'
    protocol_label_replacement['DNSCrypt'] = 'DNSCrypt'
    protocol_label_replacement['DOHOT'] = 'DNS-over-HTTPS over Tor (DOHOT)'
    protocol_label_replacement['ODOH-NoCR'] = 'ODOH Without Connection Reuse'
    for protocol, result in protocol_network_performance.items():
        # if protocol in ["ODOH", "ODOH-4G", "ODOH-3G", "ODOH-2G", "DOH-2G", "DOH", "DOH-3G", "DOH-4G"]:
        # if protocol in ["ODOH-Average", "ODOHLowLatency-Proxy", "ODOHLowLatency-ProxyTarget"]:
        # if protocol in ["ODOH", "DOH", "pDOH", "ODOHse", "DNSCrypt", "DOHOT"]:
        if protocol in ["ODOH", "ODOH-NoCR"]:
            response_times = []
            for key, value in result.items():
                response_times.extend(value)
            for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
                print("{} - [{} Percentile] : {}".format(protocol, percentile_value, percentile(response_times, percentile_value)))
            X, Y = cdf(response_times)
            index = len(Y)
            for i, x in enumerate(Y):
                if x <= 0.90:
                    index = i
            X = X[:index]
            Y = Y[:index]
            linestyle = '-'
            protocol = protocol_label_replacement[protocol]
            if protocol == "ODOH-Average":
                linestyle = ":"
            if protocol == "ODOHse":
                protocol = "Cleartext-ODOH"
            if protocol in ["DOH", "DOH-2G", "DOH-3G", "DOH-4G"]:
                linestyle = "--"
            ax.plot(X, Y, label='{}'.format(protocol), linestyle=linestyle)
            X, Y = cdf(response_times)
            X = X[index:]
            Y = Y[index:]
            ax2.plot(X, Y)
    # ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.legend()
    ax2.set_xscale('log')
    ax.set_title('Impact of Response Time due to Connection Reuse')
    ax.set_xlabel('Time (ms)')
    # ax.set_xscale('log')
    ax.set_ylabel('CDF')
    if with_failures:
        plt.savefig('logs/results/all_clients_response_times_cdf_compare_with_failures_log.png', bbox_inches='tight')
    else:
        plt.savefig('logs/results/all_clients_response_times_compare_cdf_log.png', bbox_inches='tight')


def plot_resolver_wise_protocol_comparision_as_cdf(df, with_failures=False):
    protocols_available = list(df['ProtocolType'].value_counts().to_dict().keys())

    protocol_resolver_performance = defaultdict(list)

    for protocol in protocols_available:
        protocol_filtered_df = df[df['ProtocolType'] == protocol]
        available_resolvers = list(protocol_filtered_df['TargetUsed'].value_counts().to_dict().keys())
        for resolver in available_resolvers:
            filtered_data = df[(df['ProtocolType'] == protocol) & (df['TargetUsed'] == resolver)]
            key = '{}: {}'.format(protocol, resolver)
            for filter_type in ['network_time']:
                values = sorted(filtered_data[filter_type].to_list())
                protocol_resolver_performance[key].extend(values)

    import seaborn as sns

    NUM_COLORS = 50
    clrs = sns.color_palette('husl', n_colors=NUM_COLORS)

    fig, ax = plt.subplots(nrows=1, ncols=1)
    i = 0
    for protocol_resolver, values in protocol_resolver_performance.items():
        X, Y = cdf(values)
        line = ax.plot(X, Y, label="{}".format(protocol_resolver))
        line[0].set_color(clrs[i])
        i += 1
    ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    ax.set_title('Protocol Impact by Resolver Choice')
    ax.set_xlabel('Time (ms)')
    ax.set_xscale('log')
    ax.set_ylabel('CDF')
    plt.savefig('logs/results/resolver_protocol_impact.png', bbox_inches='tight')


def plot_boxplot_protocol_wise_comparision(successful_queries_filtered, with_failures):
    protocols_available = list(successful_queries_filtered['ProtocolType'].value_counts().to_dict().keys())

    protocol_resolver_performance = defaultdict(list)

    # protocols_chosen = ["ODOH", "ODOH-4G", "ODOH-3G", "ODOH-2G", "DOH", "pDOH", "ODOHse", "DNSCrypt", "DOHOT"]
    protocols_chosen = ["ODOH", "DOH", "pDOH"]
    colors = ['red', 'green', 'blue', 'purple', 'magenta', 'orange', 'pink']
    # protocols_chosen = ["ODOH", "DOH", "pDOH"]
    # protocols_chosen = ["ODOH", "ODOH-4G", "ODOH-3G", "ODOH-2G"]

    cachehit_response = 10
    nine_five_average = 58
    missed_response_average = 120

    for protocol in protocols_available:
        if protocol in protocols_chosen:
            filtered_data = successful_queries_filtered[successful_queries_filtered['ProtocolType'] == protocol]
            key = '{}'.format(protocol)
            for filter_type in ['network_time']:
                values = sorted(filtered_data[filter_type].to_list())
                protocol_resolver_performance[key].extend(values)
                if protocol == "pDOH":
                    num_values = len(values)
                    cachehit_split = int(0.686873 * num_values)  # Cache hit based prediction
                    nine_five_split = int(0.95 * num_values)     # p99th latency for communications to Nameservers
                    anticipated_values = []
                    for v in values:
                        if len(anticipated_values) <= cachehit_split:
                            anticipated_values.append(v + cachehit_response)
                        elif len(anticipated_values) > cachehit_split and len(anticipated_values) <= nine_five_split:
                            anticipated_values.append(v + nine_five_average)
                        else:
                            anticipated_values.append(v + missed_response_average)
                    protocol_resolver_performance["Expected ODOH"].extend(anticipated_values)

    rows = []
    for key, values in protocol_resolver_performance.items():
        if key == "ODOHse":
            key = "ClearText-ODOH"
        for value in values:
            rows.append([key, value])
        if key == "Expected ODOH":
            for percentile_value in [50, 70, 75, 80, 85, 90, 95, 99]:
                print("{} - [{} Percentile] : {}".format(key, percentile_value, percentile(sorted(values), percentile_value)))

    merged_df = pandas.DataFrame(data=rows, columns=['Protocol', 'Time'])
    # import seaborn as sns
    # fig, ax = plt.subplots(nrows=1, ncols=1)
    # ax = sns.boxplot(y=merged_df['Protocol'], x=merged_df['Time'])
    # ax.set_xlabel("Response Time (ms)")
    # ax.set_xscale('log')
    # # ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
    # if with_failures:
    #     plt.savefig('logs/results/boxplots/all_protocols_latency_boxplot_failures_log.png', bbox_inches='tight')
    # else:
    #     plt.savefig('logs/results/boxplots/all_protocols_latency_boxplot_log.png', bbox_inches='tight')

    fig, ax = plt.subplots(nrows=1, ncols=1)
    protocols_existing = merged_df['Protocol'].to_dict().keys()
    color_dict = {}
    color_dict['ODOH'] = 'red'
    color_dict['ODOH-UW'] = 'aqua'
    color_dict['ODOH-UW-GCP'] = 'grey'
    color_dict['ODOH-UW-GCP-UT'] = 'forestgreen'
    color_dict['DOH'] = 'green'
    color_dict['pDOH'] = 'blue'
    color_dict['Cleartext-ODOH'] = 'maroon'
    color_dict['DNSCrypt'] = 'magenta'
    color_dict['DOHOT'] = 'orange'
    color_dict['Expected ODOH'] = 'forestgreen'
    for protocol in protocol_resolver_performance.keys():
        values = protocol_resolver_performance[protocol]
        X, Y = cdf(values)
        # Trim above 90th percentile
        # index = len(Y)
        # for i, x in enumerate(Y):
        #     if x < 0.9:
        #         index = i
        # X = X[:index]
        # Y = Y[:index]
        # X, Y = cdf(values[:index])
        linestyle = "-"
        if protocol == "ODOHse":
            protocol = "Cleartext-ODOH"
        if protocol == "Expected ODOH":
            linestyle = ":"
        ax.plot(X, Y, label="{}".format(protocol), linestyle=linestyle, color=color_dict[protocol])
    ax.legend()
    ax.set_title('Impact of Co-location on ODOH')
    ax.set_xlabel('Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_xscale('log')
    plt.savefig('logs/results/boxplots/odoh_prediction.png', bbox_inches='tight')


def process_dataframe_client_logs(df, with_failures=False):
    if not with_failures:
        successful_queries_filtered = df[df['Status'] == True]
    else:
        successful_queries_filtered = df
    available_clients = list(successful_queries_filtered['ClientName'].value_counts().to_dict().keys())
    available_protocols = list(successful_queries_filtered['ProtocolType'].value_counts().to_dict().keys())
    successful_queries_filtered['question_compute'] = (successful_queries_filtered['ClientQueryEncryptionTime'] - successful_queries_filtered['Start'])/(1000.0*1000.0)  # for ms
    successful_queries_filtered['network_time'] = (successful_queries_filtered['ClientDownstreamResponseTime'] - successful_queries_filtered['ClientUpstreamRequestTime'])/(1000.0*1000.0)  # for ms
    successful_queries_filtered['answer_compute'] = (successful_queries_filtered['ClientAnswerDecryptionTime'] - successful_queries_filtered['ClientDownstreamResponseTime'])/(1000.0*1000.0)  # for ms

    protocol_network_performance = defaultdict()

    for protocol in available_protocols:
        # if protocol in ["ODOH", "ODOHLowLatency-Proxy", "ODOHLowLatency-ProxyTarget", "ODOH-Average"]:
        protocol_filtered_df = successful_queries_filtered[successful_queries_filtered['ProtocolType'] == protocol]
        network_performance = defaultdict(list)
        for client in available_clients:
            filtered_df = protocol_filtered_df[protocol_filtered_df['ClientName'] == client]
            for filter_type in ['network_time']:
                values = sorted(filtered_df[filter_type].to_list())
                network_performance[client].extend(values)
        protocol_network_performance[protocol] = network_performance

    plot_protocol_wise_clients_comparision_as_cdf(protocol_network_performance, with_failures)
    plot_protocol_wise_all_comparision_as_cdf(protocol_network_performance, with_failures)
    plot_resolver_wise_protocol_comparision_as_cdf(successful_queries_filtered, with_failures)
    plot_boxplot_protocol_wise_comparision(successful_queries_filtered, with_failures)


if __name__ == '__main__':
    odoh_df = pandas.read_csv('logs/odoh_logs_dataframe.csv')
    odohllp_df = pandas.read_csv('logs/odohlowlatency_proxy_logs_dataframe.csv')
    odohllpt_df = pandas.read_csv('logs/odohlowlatency_proxytarget_logs_dataframe.csv')
    odoh4g_df = pandas.read_csv('logs/odoh_4g_logs_dataframe.csv')
    odoh3g_df = pandas.read_csv('logs/odoh_3g_logs_dataframe.csv')
    odoh2g_df = pandas.read_csv('logs/odoh_2g_logs_dataframe.csv')
    odohuw = pandas.read_csv('logs/odoh_uw_logs_dataframe.csv')
    odohuwgcp = pandas.read_csv('logs/odoh_uwgcp_logs_dataframe.csv')
    odohuwgcput = pandas.read_csv('logs/odoh_uwgcput_logs_dataframe.csv')

    doh2g = pandas.read_csv('logs/doh_2g_logs_dataframe.csv')
    doh3g = pandas.read_csv('logs/doh_3g_logs_dataframe.csv')
    doh4g = pandas.read_csv('logs/doh_4g_logs_dataframe.csv')
    odohnocr = pandas.read_csv('logs/odoh_nocr_logs_dataframe.csv')  # ODOH without connection reuse

    # Useful for Figure 2: Comparison of Impact of ODOH due to Proxy-Target selection
    odoh_av = pandas.concat([odoh_df, odohllp_df, odohllpt_df])
    odoh_av['ProtocolType'] = 'ODOH-Average'

    # Useful for Figure 3: Comparison of ODOH to other available DNS Protocols
    doh_df = pandas.read_csv('logs/doh_logs_dataframe.csv')
    pdoh_df = pandas.read_csv('logs/pdoh_logs_dataframe.csv')
    odohse_df = pandas.read_csv('logs/odohse_logs_dataframe.csv')
    dohot_df = pandas.read_csv('logs/dohot_logs_dataframe.csv')
    dnscrypt_df = pandas.read_csv('logs/dnscrypt_logs_dataframe.csv')

    # Useful for figure 5: Target-resolver resolution time.
    target_odohse_df = pandas.read_csv('logs/odohse_target_logs_dataframe.csv')
    target_odoh_df = pandas.read_csv('logs/odoh_target_logs_dataframe.csv')
    target_odoh4g_df = pandas.read_csv('logs/odoh_4g_target_logs_dataframe.csv')
    target_odoh3g_df = pandas.read_csv('logs/odoh_3g_target_logs_dataframe.csv')
    target_odoh2g_df = pandas.read_csv('logs/odoh_2g_target_logs_dataframe.csv')

    df = pandas.concat([odoh_df, odohuw, odohuwgcp, odohuwgcput, doh_df, pdoh_df, odohse_df, odohllp_df, odohllpt_df,
                        odoh_av, dohot_df, dnscrypt_df, odoh4g_df, odoh3g_df, odoh2g_df, doh2g, doh3g, doh4g, odohnocr])

    server_df = pandas.concat([target_odohse_df, target_odoh_df, target_odoh4g_df, target_odoh2g_df, target_odoh3g_df])

    process_dataframe_client_logs(df)
    # process_dataframe_client_logs(df, with_failures=True)

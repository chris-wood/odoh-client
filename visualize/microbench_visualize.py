import pandas
import numpy
import matplotlib.pyplot as plt
import seaborn as sns


def percentile(data_row, percentile_value=95):
    return numpy.percentile(data_row, percentile_value)


def cdf(data):
    n = len(data)
    x = numpy.sort(data) # sort your data
    y = numpy.arange(1, n + 1) / n # calculate cumulative probability
    return x, y


def read_microbenchmark_file(filename='keygeneration.csv', filedir='logs/microbench'):
    filepath = "{}/{}".format(filedir, filename)
    df = pandas.read_csv(filepath)
    return df


def concatenate_column_values(row):
    kem = row['KEM']
    kdf = row['KDF']
    aead = row['AEAD']
    s = "{}/{}/{}".format(kem, kdf, aead)
    return s


def process_keygeneration_data(df):
    df['Category'] = df.apply(concatenate_column_values, axis=1)
    KEMIDS = list(df['KEM'].value_counts().to_dict().keys())
    KDFIDS = list(df['KDF'].value_counts().to_dict().keys())
    AEADIDS = list(df['AEAD'].value_counts().to_dict().keys())
    print(df)
    fig, ax = plt.subplots(nrows=len(KEMIDS), ncols=1, figsize=(16, 16))
    count = 0
    for kem in KEMIDS:
        for kdf in KDFIDS:
            for aead in AEADIDS:
                filtered_df = df[(df['KEM'] == kem) & (df['KDF'] == kdf) & (df['AEAD'] == aead)]
                filtered_df['Category'] = "{}/{}/{}".format(kem, kdf, aead)
                key_generation_times = sorted(filtered_df['Time'].to_list())
                X, Y = cdf(key_generation_times)
                ax[count].plot(X, Y, label='{} / {} / {}'.format(kem, kdf, aead))
                # ax[count] = sns.boxplot(x='Category', y='Time', data=chosen_df)
        ax[count].set_xscale('log')
        ax[count].legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
        count += 1
    plt.savefig('logs/results/microbench/{}.png'.format('Key Generation Time'), bbox_inches='tight')

    chosen_df = df[['Category', 'Time']]
    fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(16, 16))
    ax = sns.boxplot(x='Time', y='Category', data=chosen_df)
    ax.set_xscale('log')
    plt.savefig('logs/results/microbench/{}.png'.format('Key Generation Time Box Plot'), bbox_inches='tight')


def read_and_plot_encryption_decryption_microbenchmark(filename='micro-encryption.csv', filedir='logs/microbench'):
    filepath = "{}/{}".format(filedir, filename)
    df = pandas.read_csv(filepath)
    available_modes = list(df['Mode'].value_counts().to_dict().keys())
    available_kemkdfaead = list(df['KEMKDFAEAD'].value_counts().to_dict().keys())
    import seaborn as sns

    colors = sns.color_palette("Set1", len(available_kemkdfaead))

    fig, ax = plt.subplots(nrows=3, ncols=3, figsize=(20, 20))
    row_index = 0
    col_index = 0
    for kemkdf in available_kemkdfaead:
        index = 0
        for mode in available_modes:
            linestyle = '-'
            if mode == 'Decryption':
                linestyle = ':'
            filtered_df = df[(df['Mode'] == mode) & (df['KEMKDFAEAD'] == kemkdf)]
            time_in_ns = filtered_df['Time'].to_list()
            time_in_us = [float(x) / (1000.0 * 1000.0) for x in time_in_ns]
            sorted_times_in_us = sorted(time_in_us)
            X, Y = cdf(sorted_times_in_us)
            for p in [50, 70, 75, 80, 85, 90, 95, 99]:
                print("[{}] {} @ {} Percentile: {} us".format(mode, kemkdf, p, percentile(sorted_times_in_us, p)))
            ax[row_index][col_index].plot(X, Y, label='{}'.format(mode, kemkdf), linestyle=linestyle, color=colors[index])
            index+=1
        ax[row_index][col_index].legend(fancybox=True)
        ax[row_index][col_index].set_title('{}'.format(kemkdf))
        col_index = (col_index + 1) % 3
        if col_index == 0:
            row_index = (row_index + 1) % 3
        kemkdf = kemkdf.replace('/', '-')
        ax[row_index][col_index].set_xscale('log')
        ax[row_index][col_index].set_xlabel('Time(ms)')
        ax[row_index][col_index].set_ylabel('CDF')
    plt.savefig('logs/results/microbench/{}.png'.format('AllMatrix'), bbox_inches='tight')

    fig, ax = plt.subplots(nrows=1, ncols=1)
    index = 0
    for kemkdf in available_kemkdfaead:
        for mode in available_modes:
            linestyle = '-'
            if mode == 'Decryption':
                linestyle = ':'
            filtered_df = df[(df['Mode'] == mode) & (df['KEMKDFAEAD'] == kemkdf)]
            time_in_ns = filtered_df['Time'].to_list()
            time_in_us = [float(x) / (1000.0) for x in time_in_ns]
            sorted_times_in_us = sorted(time_in_us)
            X, Y = cdf(sorted_times_in_us)
            ax.plot(X, Y, label='{} {}'.format(mode, kemkdf), linestyle=linestyle, color=colors[index])
        index+=1
        ax.legend(fancybox=True, loc='center left', bbox_to_anchor=(1.0, 0.5))
        ax.set_title('{}'.format("Encryption & Decryption Overhead Microbenchmark"))
        kemkdf = kemkdf.replace('/', '-')
        ax.set_xscale('log')
        ax.set_xlabel('Time($\mu$s)')
        ax.set_ylabel('CDF')
    plt.savefig('logs/results/microbench/{}.png'.format('all_compute_microbenchmark'), bbox_inches='tight')


if __name__ == '__main__':
    # df = read_microbenchmark_file()
    # process_keygeneration_data(df)
    read_and_plot_encryption_decryption_microbenchmark()
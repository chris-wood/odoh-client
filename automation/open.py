import json
import random

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.support.ui import WebDriverWait

PROTOCOL = "ODOH"
LOG_NAME = "Chrome-500.log"
LOG_FILE = "{}/{}".format(PROTOCOL, LOG_NAME)


def read_dataset(filename='dataset.csv'):
    lines = [line.rstrip() for line in open(filename)]
    return lines


def main():
    domains = read_dataset()[:2000]
    random.shuffle(domains)
    domains = domains[:500]
    domains = ["https://{}".format(x) for x in domains]

    # Allow experiments to work with both Firefox and Chrome.
    results = []
    # Uncomment the two lines below if measurements need to be done with adblock enabled.
    # profile = FirefoxProfile()
    # profile.add_extension(extension='automation/adblock_for_firefox-4.20.0-fx.xpi')

    # Default to Chrome to run the page load time measurements.
    with webdriver.Chrome() as driver:
        wait = WebDriverWait(driver, 10)
        for domain in domains:
            try:
                print("Requesting {}".format(domain))
                driver.get(domain)
                timer = driver.execute_script("return window.performance.timing")
                timer['Hostname'] = domain
                results.append(timer)
            except WebDriverException:
                pass
        with open("logs/{}".format(LOG_FILE), "a+") as f:
            lines = []
            for result in results:
                lines.append(json.dumps(result) + "\n")
            f.writelines(lines)
        print('Completed Write')


main()

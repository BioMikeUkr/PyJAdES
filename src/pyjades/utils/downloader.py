import os
import requests


def download_certificate(url, output_file):
    """
    Downloads a certificate from the given URL and saves it to a file.
    :param url: The URL of the certificate.
    :param output_file: The file where the certificate will be saved.
    """
    try:
        if not os.path.exists(output_file):
            response = requests.get(url)
            if response.status_code == 200:
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                print(f"Certificate downloaded and saved as {output_file}")
            else:
                print(f"Failed to download certificate from {url}. Status code: {response.status_code}")
        else:
            print(f"Certificate {output_file} already exists in cache.")
    except Exception as e:
        print(f"Error while downloading certificate: {e}")

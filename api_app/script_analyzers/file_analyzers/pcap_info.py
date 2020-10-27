import os
import requests
import logging
import base64
import json
import time

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import FileAnalyzer
from api_app.helpers import get_binary
from intel_owl import secrets

logger = logging.getLogger(__name__)


class PcapInfo(FileAnalyzer):
    base_url: str = "https://api.packettotal.com/v1"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "PACKETTOTAL_API_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        # max no. of tries when polling for result
        self.max_tries = additional_config_params.get("max_tries", 200)
        # interval b/w HTTP requests when polling
        self.poll_distance = 3
        self.is_test = additional_config_params.get("is_test", False)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: '{self.api_key_name}'"
            )

        return self.__analyze_pcap_file()

    def __analyze_pcap_file(self):
        session = requests.session()
        session.headers["x-api-key"] = self.__api_key
        session.headers["Content-Type"] = 'application/json'

        pcap_base64 = base64.b64encode(get_binary(self.job_id))
        pcap_base64 = pcap_base64.decode('utf-8')
        body = {
            'pcap_base64': pcap_base64
        }
        pcap_name = self.filename if self.filename else self.md5
        body['pcap_name'] = pcap_name

        logger.info(f"pcap md5 {self.md5} sending file for analysis")
        response = session.post(self.base_url + '/analyze/base64', data=json.dumps(body))
        if response.status_code != 201:
            raise AnalyzerRunException(
                f"failed analyze request, status code {response.status_code}"
        )

        for count in range(self.max_tries):
            if response.status_code != 200:
                time.sleep(self.poll_distance)
                logger.info(
                    f"pcap md5 {self.md5} polling for result try #{count + 1}"
                )
                # TO DO
                # Test API and add result_url

            if response.status_code != 200 and not self.is_test:
                raise AnalyzerRunException("received max tries attempts")

        return response.json()
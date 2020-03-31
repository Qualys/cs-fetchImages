#!/usr/bin/python

# imports
import sys, json, requests, csv, os, yaml, time
import argparse
import configparser
from datetime import datetime
from os import path
import logging.config

def setup_logging(default_path='./config/logging.yml',default_level=logging.INFO,env_key='LOG_CFG'):
  """Setup logging configuration"""
  if not os.path.exists("log"):
    os.makedirs("log")
  path = default_path
  value = os.getenv(env_key, None)
  if value:
    path = value
    if os.path.exists(path):
      with open(path, 'rt') as f:
          config = yaml.safe_load(f.read())
          logging.config.dictConfig(config)
    else:
      logging.basicConfig(level=default_level)


class Config:

  def __init__(self, configPath):
    config = configparser.ConfigParser()
    config.read(configPath)
    self.__configPath = configPath

  def ReadConfig(self):
    config = configparser.ConfigParser()
    config.read(self.__configPath)

    cmsConfig = config['cms']

    for configKey in self.__configKeys:
      if configKey not in cmsConfig:
        print(configKey + " cannot be empty")
        exit(1)
      if not cmsConfig[configKey]:
        print(configKey + "  value missing in config")
        exit(1)
    try:
        self.__portalUser = os.environ["QUALYS_API_USERNAME"]
        #password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
        self.__portalPass = os.environ["QUALYS_API_PASSWORD"]
    except KeyError as e:
        logger.critical("Critical Env Variable Key Error - missing configuration item {0}".format(str(e)))
        logger.critical("Please review README for required configuration to run script")
        sys.exit(1)
    #self.__portalUser = cmsConfig["portal_user"]
    #self.__portalPass = cmsConfig["portal_pass"]
    self.__updated = cmsConfig["updated"]
    self.__batchSize = cmsConfig["batch_size"]
    self.__gatewayUrl = cmsConfig["gateway_url"]
    self.__scannedOnly = int(cmsConfig["scanned_only"])
    self.__csv = cmsConfig["csv"]

    if int(self.__batchSize) > 1000:
      print("Batch size too large. Exiting..")
      exit(1)

  def GetPortalUser (self):
    return self.__portalUser

  def GetPortalPassword (self):
    return self.__portalPass

  def GetUpdated(self):
    return self.__updated

  def GetBatchSize(self):
    return self.__batchSize

  def GetGatewayUrl(self):
    return self.__gatewayUrl

  def GetScannedOnly(self):
    return self.__scannedOnly

  def SetConfig(self, updated):
      f=open("./config/Last_Updated_Result", "w")
      f.write(str(updated))
      f.close()
  def writeCsv(self):
      return self.__csv

  __configKeys = ["updated", "batch_size", "gateway_url", "scanned_only", "csv"]

class CSAPI:
  def __init__(self, config):

    self.__portalUser = config.GetPortalUser()
    self.__portalPass = config.GetPortalPassword()
    self.__portalApi = config.GetGatewayUrl() + "/csapi/v1.2/images"

    self.__pageSize = config.GetBatchSize()
    self.__gatewayUrl = config.GetGatewayUrl() + "/auth"
    self.__scannedOnly = config.GetScannedOnly()

    if path.exists("./config/Last_Updated_Result"):
        f=open("./config/Last_Updated_Result", "r")
        contents=f.read()
        print("\nContents of Last_Updated_Result = {}\n\n".format(str(contents)))
        f.close()
        self.__lastUpdated = contents
    else:
        self.__lastUpdated = config.GetUpdated()

  def Authenticate(self):
    session = requests.Session()
    authComplete = False
    retryLimit = 5
    retry = 0
    while not authComplete:
        try:
          header = {"Content-Type": "application/x-www-form-urlencoded"}
          api = self.__gatewayUrl
          requestBody = "username=" + self.__portalUser + "&password=" + self.__portalPass + "&token=true"
          response = session.post(api, data=requestBody, headers=header, verify=False)
          if response.status_code == 200 or response.status_code == 201:
            token = response.content.decode('utf-8')
            print("Token: " + token)
            authComplete = True
          else:
            logger.warning("Authentication Failed. Auth Response: " + str(response.status_code))
            exit(1)

        except Exception as e:
          logger.error("Failed send request, error: " + str(e))
          retry += 1
          if retry > retryLimit:
              print("Authentication Token Error Limit Exceded...exit(1)")
              exit(1)
          time.sleep(5)
    return token

  def Execute(self, token):
    emptyResults = []
    with requests.Session() as session:
      try:
        bearerToken = "Bearer " + token
        header = {"Content-Type": "application/json", "Authorization": bearerToken }
        maxUpdated = self.__lastUpdated

        while True: #Fetch all the results from the last updated date
          filterString = ""
          if self.__scannedOnly == 1:
            filterString = "?pageNumber=1&pageSize=" + self.__pageSize + "&filter=not%20lastScanned%20is%20null%20AND%20updated%3E" + maxUpdated + "&sort=updated%3Aasc"
          else:
            filterString = "?pageNumber=1&pageSize=" + self.__pageSize + "&filter=updated%3E" + maxUpdated + "&sort=updated%3Aasc"
          apiUrl = self.__portalApi + filterString
          # print(apiUrl)
          response = session.get(apiUrl, headers=header, verify=False)
          logger.info("Response Code: " + str(response.status_code))

          if response.status_code == 204:
            return maxUpdated, emptyResults # No content
          elif response.status_code == 200:
            if response.content.decode('utf-8') == '':
              return maxUpdated, emptyResults # No records
            fetchResult = json.loads(response.content.decode('utf-8'))
            logger.info("Result Size: " + str(len(fetchResult["data"])))
            results = fetchResult["data"]
            #print (fetchResult["data"])

            print ("Results is type {}".format(str(type(results))))
            print ("Results is length {}".format(str(len(results))))
            #for result in results:
            #    print ("Results is type {}".format(str(type(result))))
            #    print ("Keys from result \n {} \n".format(str(result.keys())))


            if len(fetchResult["data"]) > 0:

              for result in fetchResult["data"]:
                # print(result["lastScanned"])
                updated = result["updated"]
                if (updated is not None) and (updated > maxUpdated):
                  maxUpdated = updated #Note the max updated date and use it next time
              return maxUpdated, fetchResult["data"]

            else:
              return maxUpdated, fetchResult["data"]
          else:
            logger.warning("Failed to fetch the result")
      except Exception as e:
        logger.error("Failed to send request, error: " + str(e))
        return maxUpdated, emptyResults

  def flattenResults(self, results):
    flatResults = []
    d = {}
    for result in results:
        vulnCounts = result['vulnerabilities']
        logger.info(vulnCounts)
        for k, v in result.items():
            d[k] = v
            if isinstance(d[k], dict):
                for kk, vv in vulnCounts.items():
                    d[kk] = vv
        if 'vulnerabilities' in d.keys():
            d.pop('vulnerabilities', None)

        print(d)
        flatResults.append(dict(d))
        d.clear()
    logger.info(flatResults)
    return flatResults

  def writeCsv(self, findings):
    if not os.path.exists("reports"):
      os.makedirs("reports")
    csvHeaders = findings[0].keys()

    logger.info("csvHeaders = {} \n".format(findings[0].keys))
    if not os.path.exists("reports"):
      os.makedirs("reports")
    out_file = "reports/Image_Vulnerability_Summary_Report_" + time.strftime("%Y%m%d-%H%M%S") + ".csv"
    ofile = open(out_file, "w")
    writer = csv.DictWriter(ofile, csvHeaders)
    writer.writeheader()
    writer.writerows(findings)
    ofile.close()

def main():
  if len(sys.argv) > 1:
    configPath = sys.argv[1]
  else:
    configPath = "./config/config.conf"
  config = Config(configPath)
  config.ReadConfig()
  CSAPIcaller = CSAPI(config)
  token = CSAPIcaller.Authenticate()
  lastUpdated, results = CSAPIcaller.Execute(token)
  logger.info("Done! Fetched images up to " + lastUpdated)

  logger.debug("Type of results = {}".format(type(results)))
  logger.debug(type(results))
  writeCsv = config.writeCsv()
  logger.info("writeCsv = {}".format(writeCsv))
  if writeCsv and results:
    flatResults = CSAPIcaller.flattenResults(results)
    CSAPIcaller.writeCsv(flatResults)
  elif writeCsv and not results:
    logger.info("No results returned to write to CSV")
  else:
    print (results)
  config.SetConfig(lastUpdated)


if __name__ == "__main__":
  setup_logging()
  logger = logging.getLogger(__name__)
  main()

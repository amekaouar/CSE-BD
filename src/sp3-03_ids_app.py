#Executive Certificate Big Data - Centrale Supelec - Octobre 2018
#Détection d’intrusion réseau à l’aide de l’apprentissage automatique
#Fichier : sp3-03_ids_app.py
#Auteur : Ahmed Mekaouar

from flask import Flask, request
import pandas as pd
import numpy as np
import json
from sklearn.externals import joblib
import os
import time
import ctypes
MB_OK = 0x0
MB_OKCXL = 0x01
MB_YESNOCXL = 0x03
MB_YESNO = 0x04
MB_HELP = 0x4000
ICON_EXLAIM=0x30
ICON_INFO = 0x40
ICON_STOP = 0x10


app = Flask(__name__)
print (" IDS Application - Executive certificate Big Data - Centrale Supelec")
print (" A. Mekaouar")
# Load Model File
model_path = os.path.join(os.path.pardir,'models')
model_filepath = os.path.join(model_path, 'classification_DT_model.pkl')
log_filepath = os.path.join(os.path.pardir,'data','api-test', 'flow.log')

ids_model = joblib.load(model_filepath)

f=open(log_filepath,'r')
while True:
    line = ''
    while len(line) == 0 or line[-1] != '\n':
        tail = f.readline()
        if tail == '':
            time.sleep(0.1) 
            continue
        line += tail
        if (tail!="\n"):
            li = tail.split(',')
            prediction = ids_model.predict(np.asarray(li).reshape(1,-1))
            pred = prediction.tolist()[0]
            message = pred + " attack probably on going, please check!"
            if (pred !='BENIGN'):
                ctypes.windll.user32.MessageBoxW(0, message, "Security Alert!", MB_OK|ICON_EXLAIM)

if __name__ == '__main__':
    app.run(port=9999, debug=True)
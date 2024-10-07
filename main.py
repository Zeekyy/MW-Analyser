import shutil
import tkinter as tk
from tkinter import filedialog
import requests
import time
import os
from dotenv import load_dotenv
import concurrent.futures 
import datetime
import logging
from dotenv import load_dotenv
from tqdm import tqdm




load_dotenv()
#API_KEY = os.getenv("API_KEY")  
analysis_result = None  
analysis_resultF = None

logging.basicConfig(
    filename='app.log',      
    level=logging.INFO,      
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_api_key():
    load_dotenv()

    api_key = os.getenv("API_KEY")

    if not api_key or len(api_key) != 64:
        while not api_key or len(api_key) != 64:
            api_key = input("API Keys not found.Please enter your VirusTotal API Keys: ")

        if len(api_key) == 64:
            with open(".env", "a") as env_file:
                env_file.write(f"\nAPI_KEY={api_key}")
            print("API keys saved :)")
    else:
        print("API keys found.")

    return api_key

API_KEY = check_api_key()

def menu():

    now = datetime.datetime.now()
    date_time_str = now.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{date_time_str}.txt"

    while True:
        print("")
        print("1. Files Scanner")
        print("2. Reportory Scanner")
        print("3. Get a report")
        print("4. Exit")
        print("")

        try:
            choise = int(input("What would you like to do? "))
        except ValueError:
            print("Please enter a valid number.")
            continue

        if choise == 1:
            selection = files_select()
            if selection:
                analysis_result = files_scanner(selection)  
                if analysis_result and len(analysis_result) > 0: 
                    malware_rm(analysis_result, selection)
        elif choise == 2:
            selection = folder_select()
            if selection:
                analysis_resultF, filescan = scan_directory_multithread(selection)  
                if analysis_resultF and len(analysis_resultF) > 0:
                    for analysis, file_path in zip(analysis_resultF, filescan): 
                        malware_rm(analysis, file_path)
        elif choise == 3:
            choise = input("Which result would you like? (P for program / R for directory)")
            if choise == "P":
                if analysis_result: 
                    with open(filename, "w") as fichier:
                        #generate_report(analysis_result)
                        fichier.write(generate_report(analysis_result))
                else:
                    print("There is no available analysis.")
            elif choise == "R":
                if analysis_resultF and len(analysis_resultF) > 0:
                    with open(filename, "w") as fichier:
                        fichier.write(generate_reportF(analysis_resultF))
                else:
                    print("There is no available analysis.")
            else:
                print("Error, please enter a valid letter.")         
        elif choise == 4:
            quit()


def files_select():
    selection = None
    selection = filedialog.askopenfilename(title="Select a program")

    return selection  

def folder_select():
    selection = None
    selection = filedialog.askdirectory(title="Select a directory")

    return selection 

def folder_scanner(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}

    try:
        with open(file_path, 'rb') as file_to_scan:
            files = {'file': file_to_scan}
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            result = response.json()
            analysis_id = result['data']['id']
            logging.info( f"Analysis ID: " + analysis_id + "for:" + file_path)

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"            

            with tqdm(total=100, desc="Waiting for analysis...", colour="blue") as progress_bar:
                analyse_complete = False
                attempt = 0

                while not analyse_complete:
                    response = requests.get(analysis_url, headers=headers)

                    if response.status_code == 200:
                        analysis_resultF = response.json()

                        status = analysis_resultF["data"]["attributes"]["status"]
                        if status == "completed":
                            analyse_complete = True
                            print("")
                            print(f"Complete results successfully retrieved.")
                            logging.info(f"Complete results for: " + file_path + "successfully retrieved")
                            return analysis_resultF

                    attempt += 1
                    progress_bar.update(1)
                    time.sleep(5)
            
            print(f"Erreur while retrieving result.")
            logging.info(f"Erreur while retrieving result for: "+ file_path + response.status_code + response.text)

        else:
            print(f"Error while sending files: ")
            logging.info(f"Error while sending files for: "+ file_path + response.status_code + response.text)

    except Exception as e:
        print(f"Error while analysing")
        logging.info(f"Error while analysing: " + e)


def files_scanner(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": API_KEY
    }

    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            result = response.json()
            analysis_id = result['data']['id'] 
            #print(f"Analyse soumise avec succès.")
            logging.info("ID de l'analyse: " + analysis_id)

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"            

            with tqdm(total=100, desc="Waiting for analysis...", colour="blue") as progress_bar:
                analyse_complete = False
                attempt = 0

                while not analyse_complete:
                    response = requests.get(analysis_url, headers=headers)

                    if response.status_code == 200:
                        analysis_result = response.json()

                        status = analysis_result["data"]["attributes"]["status"]
                        if status == "completed":
                            analyse_complete = True
                            print("")
                            print(f"Complete results successfully retrieved.")
                            logging.info(f"Complete results for: " + file_path + "successfully retrieved")
                            return analysis_result

                    attempt += 1
                    progress_bar.update(1)
                    time.sleep(5)
            
            print(f"Erreur while retrieving result.")
            logging.info(f"Erreur while retrieving result for: "+ file_path + response.status_code + response.text)

        else:
            print(f"Error while sending files: ")
            logging.info(f"Error while sending files for: "+ file_path + response.status_code + response.text)

    except Exception as e:
        print(f"Error while analysing")
        logging.info(f"Error while analysing: " + e)


def generate_report(analysis_result):
    rapport = []
    
    data = analysis_result.get('data', {})
    attributes = data.get('attributes', {})
    results = attributes.get('results', {})
    file_info = analysis_result.get('meta', {}).get('file_info', {})
    stats = attributes.get('stats', {})

    rapport.append("="*70 + "\n")
    rapport.append("Rapport d'analyse\n")
    rapport.append("="*40 + "\n")
    rapport.append(f"SHA-256 : {file_info.get('sha256', 'N/A')}\n")
    rapport.append(f"MD5      : {file_info.get('md5', 'N/A')}\n")
    rapport.append(f"SHA-1    : {file_info.get('sha1', 'N/A')}\n")
    rapport.append(f"Taille   : {file_info.get('size', 'N/A')} octets\n")
    rapport.append("="*40 + "\n")

    rapport.append(f"\nSTATISTIQUES GLOBALES :\n")
    rapport.append(f"Malicious  : {stats.get('malicious', 0)}\n")
    rapport.append(f"Suspicious   : {stats.get('suspicious', 0)}\n")
    rapport.append(f"Non détecté  : {stats.get('undetected', 0)}\n")
    rapport.append(f"Harmless     : {stats.get('harmless', 0)}\n")
    rapport.append(f"Timeout      : {stats.get('timeout', 0)}\n")
    rapport.append(f"Non pris en charge : {stats.get('type-unsupported', 0)}\n")
    rapport.append("="*40 + "\n")

    rapport.append(f"\nDÉTAIL DES RÉSULTATS PAR MOTEUR ANTIVIRUS :\n")

    for engine_name, engine_result in results.items():
        category = engine_result.get('category', 'N/A')
        result = engine_result.get('result', 'N/A')
        version = engine_result.get('engine_version', 'N/A')
        update = engine_result.get('engine_update', 'N/A')

        rapport.append(f"Moteur : {engine_name}\n")
        rapport.append(f"  - Version du moteur : {version}\n")
        rapport.append(f"  - Mise à jour : {update}\n")
        rapport.append(f"  - Catégorie : {category}\n")
        rapport.append(f"  - Résultat : {result}\n")
        rapport.append("-" * 40 + "\n")

    rapport.append("\nFIN DU RAPPORT\n")
    rapport.append("="*70 + "\n")
    rapport.append("="*70 + "\n")
    
    return ''.join(rapport)


def generate_reportF(analysis_resultF):
    rapport = []
    
    for analysis_result in analysis_resultF:
        data = analysis_result.get('data', {})
        attributes = data.get('attributes', {})
        results = attributes.get('results', {})
        file_info = analysis_result.get('meta', {}).get('file_info', {})
        stats = attributes.get('stats', {})

        rapport.append("="*70 + "\n")
        rapport.append("Rapport d'analyse\n")
        rapport.append("="*40 + "\n")
        rapport.append(f"SHA-256 : {file_info.get('sha256', 'N/A')}\n")
        rapport.append(f"MD5      : {file_info.get('md5', 'N/A')}\n")
        rapport.append(f"SHA-1    : {file_info.get('sha1', 'N/A')}\n")
        rapport.append(f"Taille   : {file_info.get('size', 'N/A')} octets\n")
        rapport.append("="*40 + "\n")

        rapport.append(f"\nSTATISTIQUES GLOBALES :\n")
        rapport.append(f"Malicious  : {stats.get('malicious', 0)}\n")
        rapport.append(f"Suspicious   : {stats.get('suspicious', 0)}\n")
        rapport.append(f"Non détecté  : {stats.get('undetected', 0)}\n")
        rapport.append(f"Harmless     : {stats.get('harmless', 0)}\n")
        rapport.append(f"Timeout      : {stats.get('timeout', 0)}\n")
        rapport.append(f"Non pris en charge : {stats.get('type-unsupported', 0)}\n")
        rapport.append("="*40 + "\n")

        rapport.append(f"\nDÉTAIL DES RÉSULTATS PAR MOTEUR ANTIVIRUS :\n")

        for engine_name, engine_result in results.items():
            category = engine_result.get('category', 'N/A')
            result = engine_result.get('result', 'N/A')
            version = engine_result.get('engine_version', 'N/A')
            update = engine_result.get('engine_update', 'N/A')

            rapport.append(f"Moteur : {engine_name}\n")
            rapport.append(f"  - Version du moteur : {version}\n")
            rapport.append(f"  - Mise à jour : {update}\n")
            rapport.append(f"  - Catégorie : {category}\n")
            rapport.append(f"  - Résultat : {result}\n")
            rapport.append("-" * 40 + "\n")

    rapport.append("\nFIN DU RAPPORT\n")
    rapport.append("="*70 + "\n")
    rapport.append("="*70 + "\n")
    
    return ''.join(rapport)



def scan_directory_multithread(directory_path):
    filescan = []
    results = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            filescan.append(file_path)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for result in executor.map(folder_scanner, filescan):
            if result:
                results.append(result)

    return results, filescan  
    
    analysis_resultF = results if results else None  


    #with concurrent.futures.ThreadPoolExecutor() as executor:
    #    list(tqdm(executor.map(folder_scanner, filescan), total=len(filescan), desc="Scanning Files"))
    


def malware_rm(analysis_result, file_path):
    file_path = os.path.abspath(file_path)  
    print(f"Chemin absolu du fichier ou répertoire : {file_path}")
    dangerosity = 3
    stats = analysis_result.get('data', {}).get('attributes', {}).get('stats', {})
    dangerosity_count = stats.get('malicious', 0)

    if dangerosity_count >= dangerosity:
        print(f"L'application a été signalée comme malveillante par {dangerosity_count} antivirus.")
        choix = input("Voulez-vous la supprimer ? (o/n) : ").lower()

        if choix == 'o':
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path) 
                    logging.info(f"Le fichier '{file_path}' a été supprimé.")
                    print(f"L'application a été supprimée avec succès.")
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)  
                    logging.info(f"Le répertoire '{file_path}' a été supprimé.")
                    print(f"Le répertoire a été supprimé avec succès.")
                else:
                    print(f"Erreur ce n'est ni un fichier ni un répertoire valide.")
            except Exception as e:
                logging.error(f"Erreur lors de la suppression du fichier '{file_path}': {str(e)}")
                print(f"Impossible de supprimer le fichier.")
        else:
            logging.info(f"L'utilisateur a choisi de ne pas supprimer le fichier '{file_path}'.")
            print(f"Le fichier ne sera pas supprimé.")
    else:
        print("Le fichier n'a pas été détecté comme dangereux.")


menu()

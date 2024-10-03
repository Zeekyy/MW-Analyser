# How to use it

Easiest step: 
git clone https://github.com/Zeekyy/MW-Analyser.git
Lancer main.exe dans le répertoire dist
ou 
Lancer main.py avec python main.py

 # Malware-Analyser

L'application en python utilise l'API de VirusTotal pour analyser des fichiers et des répertoires entiers et permet de les supprimers ou non si elles sont flagué comme dangereuse en étant analyser par plus de 70 antivirus. 

# Fonction de l'app

check_api_key: Vérifie si une clé d'API est définis dans le programme et si ce n'est pas le cas demande à l'utilisateur de l'entrer 

files_select: Ouvre une boite de dialogue pour pouvoir séléctionner le fichier à analyser

folder_select: Ouvre une boite de dialogue pour pouvoir séléctionner le répertoire à analyser

files_scanner: Permet d'envoyer le fichier à l'API de VirusTotal, attend la fin de l'analyse et récupère le résultat

folder_scanner: Envoie l'intérieté du répertoire à l'API de VirusTotal, attend la fin de l'analyse et récupère le résultat

scan_directory_multithread: Permet d'axécuter plusieurs analyse en même temps pour optimiser le temps

generate_report/generate_reportF: Permet de générer les rapports détaillés des analyses dans un fichier txt externe

malware_rm: En se basant sur un niveau de dangerosité définit dans le code, permet de classer un fichier comme dangereux ou non, informe l'utilisateur et propose de le supprimer ou non 







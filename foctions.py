######### Projet_ete 2025 ###############################
# titre: Automatisation de la mise en correspondance entre journaux SIEM, techniques MITRE ATT&CK 
#        et la base de données VERIS pour l’identification d’incidents de sécurité.
#
# Professeur:  Jonathan Roy
# Etudiant:ILboudo Hermann Rodrigue
#########################################################



import csv
import json
import pandas as pd
from typing import  List 



# #############fonction load de fichier csv.################
# lit ligne par ligne le fichier 
#  transforme chacun de ces lignes en dictionnaire
# retourne un dicrionnaire
#########################################################
def load_CsvFile(chemin):
    with open(chemin, newline='', encoding='utf-8') as csv_file:
        return list(csv.DictReader(csv_file))

# technique_mitre= load_CsvFile('./exports_Alerts_Wazuh.csv')# prend en entrer les alertes wazhu
# veris=load_CsvFile('./veris-1.4.0_attack-16.1-enterprise.csv')# chargement des des donnees veris_mitre attack





# ##fonction MappingMitreVeris#####
# mapping alerte Wazhu et Action correspondante
# selection des colonnes cles issue du mapping
# retourne un dictionnaire 
#########################################################

def MappingMitreVeris( techinique, veries): 
    mappage= [] # dictionnaire 
    unique_id = set()# set assure unicite de chaque correspondance log et action veris
    
    for elements_mitre in techinique:
        try:
            mitre_ids = json.loads(elements_mitre['_source.rule.mitre.id']) # extrait la colonne id de mittre attact de alerte 
        except:
            continue  

        for elements_veris in veries:
            veris_id = elements_veris['attack_object_id'].strip()# extrait la colonne ID attact dans veris
             
            for mitre_id in mitre_ids:
                if mitre_id.lower() == veris_id.lower() and veris_id not in unique_id: # comparaison des deux colonnes et verification de unicite
                    unique_id.add(veris_id)
                    
                    #ajout de colonnes supplementaires dans le dictionnaire
                    mappage.append({
                        '_source.@timestamp': elements_mitre['_source.@timestamp'],
                        '_source.agent.ip': elements_mitre['_source.agent.ip'],
                        '_source.agent.id': elements_mitre['_source.agent.id'],
                        '_source.rule.description': elements_mitre['_source.rule.description'],
                        'attack_object_id': elements_veris ['attack_object_id'],
                        '_source.rule.mitre.technique': elements_mitre['_source.rule.mitre.technique'],
                        '_source.rule.mitre.tactic': elements_mitre['_source.rule.mitre.tactic'],
                        'capability_id': elements_veris ['capability_id'],
                        'capability_group': elements_veris ['capability_group'],
                        'capability_description': elements_veris ['capability_description'],
                    })
    return mappage # dictionnaire retourner contenant les colonnes selectionnees.





# ################fonction d'exportation rapport######################
# Exporte la liste de dictionnaires (mappage) vers un fichier CSV
#
#########################################################

def export_data( mappage, filename='rapport_mitre_veris11.csv'):
    
    if not mappage:                 #Vérifie si la liste 'mappage' est vide
        print(" Aucun mappage trouvé")
        return

   #Récupère les noms des colonnes à partir des clés 'mappage'
    fieldnames=mappage[0].keys()
    
    with open (filename,'w', newline='', encoding="utf-8" ) as csvf: # Ouvre le fichier CSV en mode écriture ('w')
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)#objet DictWriter pour écrire les données sous forme de dictionnaires
        
        writer.writeheader()#Écrit la ligne d'en-tête (noms des colonnes) dans le fichier CSV
        writer.writerows(mappage)# Écrit toutes les lignes de données
    print(f"Rapport exporté dans le fichier : {filename}")      
    
    
    
    
    
    
    
# ###############fonction pour extraire capability_id###################
# extrait les identifiants uniques de la colonne spécifique(capability_id) dans un fichier CSV.
# Lire le fichier CSV avec pandas et stocker les données dans un DataFrame
#########################################################

def extrat_capability(file_csv:str, element_capability: str = "capability_id" ) -> List[str]:#liste des identifiants uniques trouvés dans la colonne capability_id .

    df =pd.read_csv(file_csv, dtype=str, keep_default_na=False)
    if element_capability not in df.columns:# verifie si la colonne capability_id est dans le dataframe
        raise ValueError(f"colonne'{ element_capability}' introuvable dans {file_csv}. Colonnes: {list(df.columns)}")# gestion de erreur
   
   #Extraction des valeurs uniques de la colonne 
    capability_ids = (
        df[element_capability]
        # les regles de traitement appliquer sur la colonne
        .astype(str)# convertit en chaine de caractere
        .str.strip()#  supprime les espaces en début et fin de chaque valeur
        .replace({"": pd.NA})
        .dropna()
        .unique() #ne garde que les valeurs uniques
        .tolist() # convertit le résultat en une liste     
    )
    #Retourner la liste des identifiants uniques
    return capability_ids






################## foction de mappage capability_id et la base de donnee VERIS#########################
# Analyse le  fichier VCDB(base de donnee)  pour identifier les incidents associés à des capabilities spécifiques.
# parsing et mise en format  de la VCDB et 
##################################################################################################
def analyze_vcdb(vcdb: str, capability_ids, detect_incident: str ="incident_id", output_csv=None) :
    df = pd.read_csv(vcdb, low_memory=False)#Lire le fichier CSV VCDB dans un DataFrame pandas
    # cherche  quelles capabilities de `capability_ids` existent comme colonnes dans le DataFrame en utilisant les filtres suivant
    correspond = [element for element in capability_ids if element in df.columns]
    
    if not correspond:
        raise ValueError("aucune correspondance trouver")
    
    if detect_incident not in df.columns:# Vérifier si la colonne detect_incident
        raise ValueError(f" Colonne '{detect_incident}'introuvable dans VCDB")
        
    elemant_bool=df[correspond].astype(bool)#convertit les valeurs en True/False 
        
    acount_true =elemant_bool.sum(axis=1)#fait la somme des valeurs True (comptées comme 1) pour chaque ligne
    
    #Créer une liste des noms des capabilities "True" pour chaque incident
    capability_associr_true= elemant_bool.apply(lambda r: list(elemant_bool.columns[r.values]), axis=1)
    
    # Créer un DataFrame de sortie avec les résultats formatés  
    format_sortie1=pd.DataFrame({
        
        detect_incident: df[detect_incident].astype(str),
        "monbre_capability_true": acount_true.values,
        "capabilities": [", ".join(x) for x in capability_associr_true],
        
    })
    
    
    
    
    
    ##############FORMATAGE DU RAPPORT FINAL####################
    sortie_final = (format_sortie1[format_sortie1["monbre_capability_true"] >= 1]
           .sort_values(["monbre_capability_true", detect_incident], ascending=[False, True])
           .reset_index(drop=True))

    if output_csv:
        sortie_final.to_csv(output_csv, index=False)
    return sortie_final
    
    
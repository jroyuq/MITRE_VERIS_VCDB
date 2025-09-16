######### Projet_ete 2025 ###############################
# Titre: Automatisation de la mise en correspondance entre journaux SIEM, techniques MITRE ATT&CK 
#        et la base de données VERIS pour l’identification d’incidents de sécurité.
#
# Professeur:  Jonathan Roy
# Etudiant:ILboudo Hermann Rodrigue
#########################################################


from foctions import export_data, MappingMitreVeris, extrat_capability, analyze_vcdb,load_CsvFile

if __name__ == "__main__":
   # les appels de fonction
   technique_mitre= load_CsvFile('./exports_Alerts_Wazuh.csv')
   veris=load_CsvFile('./veris-1.4.0_attack-16.1-enterprise.csv')
   mapp= MappingMitreVeris( technique_mitre, veris)
   export_data(mapp, filename='rapport_mitre_veris11.csv')

   action_extrat = extrat_capability("rapport_mitre_veris11.csv")
    
   resulat= analyze_vcdb("vcdb.csv", action_extrat, output_csv="resultats_analyse.csv")
    
    
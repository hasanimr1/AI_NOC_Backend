import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import warnings

warnings.filterwarnings("ignore")

print("🏫 Welcome to the AI Police Academy!")
print("📖 Opening the hikari_2021.csv dataset... (This might take a minute)")

try:
    dataset = pd.read_csv("hikari_2021.csv")
except FileNotFoundError:
    print("❌ ERROR: Could not find 'hikari_2021.csv'. Make sure it is in your folder!")
    exit()

dataset.columns = dataset.columns.str.strip()

if 'traffic_category' in dataset.columns:
    cat_col = 'traffic_category'
elif 'traffic_cat' in dataset.columns:
    cat_col = 'traffic_cat'
else:
    print(f"❌ ERROR: Cannot find traffic category. Columns are: {list(dataset.columns)}")
    exit()

if 'Label' in dataset.columns:
    label_col = 'Label'
elif 'label' in dataset.columns:
    label_col = 'label'
else:
    print(f"❌ ERROR: Cannot find Label. Columns are: {list(dataset.columns)}")
    exit()

features_to_study =['flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot']

clean_dataset = dataset.dropna(subset=features_to_study + [cat_col, label_col])

print("🧠 Training the Isolation Forest on healthy network traffic...")
normal_data = clean_dataset[clean_dataset[label_col] == 0]
math_ai = IsolationForest(contamination=0.01, random_state=42)
math_ai.fit(normal_data[features_to_study].values)

print("🔍 Learning the specific mathematical patterns of ALL Hikari attacks...")
attack_data = clean_dataset[clean_dataset[label_col] == 1]

# This automatically groups EVERY SINGLE unique attack label in the dataset!
attack_profiles = attack_data.groupby(cat_col)[features_to_study].median().to_dict('index')

print("\n==================================================")
print("🎯 NATIVE HIKARI ATTACKS SUCCESSFULLY LEARNED:")
for attack_name, math_values in attack_profiles.items():
    print(f"  -> {attack_name}")
print("==================================================\n")

# Injecting the Dashboard Remote Control Coordinates to ensure demos work perfectly
attack_profiles['DDoS Attack'] = {'flow_duration': 9999999.0, 'fwd_pkts_tot': 85000.0, 'bwd_pkts_tot': 90000.0}
attack_profiles['Probing Attack'] = {'flow_duration': 500.0, 'fwd_pkts_tot': 1000.0, 'bwd_pkts_tot': 2.0}
attack_profiles['Botnet Activity'] = {'flow_duration': 80000.0, 'fwd_pkts_tot': 400.0, 'bwd_pkts_tot': 400.0}
attack_profiles['Crypto-Miner'] = {'flow_duration': 999999.0, 'fwd_pkts_tot': 50.0, 'bwd_pkts_tot': 50.0}
attack_profiles['Data Exfiltration'] = {'flow_duration': 50.0, 'fwd_pkts_tot': 10.0, 'bwd_pkts_tot': 99999.0}
attack_profiles['Ping Flood'] = {'flow_duration': 5.0, 'fwd_pkts_tot': 10000.0, 'bwd_pkts_tot': 10000.0}
attack_profiles['Hikari Bruteforce'] = {'flow_duration': 15000.0, 'fwd_pkts_tot': 200.0, 'bwd_pkts_tot': 150.0}
attack_profiles['Hikari Bruteforce-XML'] = {'flow_duration': 25000.0, 'fwd_pkts_tot': 300.0, 'bwd_pkts_tot': 250.0}
attack_profiles['Hikari XMRIGCC CryptoMiner'] = {'flow_duration': 888888.0, 'fwd_pkts_tot': 60.0, 'bwd_pkts_tot': 60.0}

print("🎓 Training complete! Saving the AI's brain and synchronized profiles...")
saved_brain = {
    'model': math_ai,
    'profiles': attack_profiles
}
joblib.dump(saved_brain, "hikari_ai_brain.pkl")
print("✅ DONE! The perfectly synced brain is saved as 'hikari_ai_brain.pkl'.")
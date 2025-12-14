import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import average_precision_score

def sort_label(str):
    if "ddos" == str:
        return 1
    return 0

def group_dst_port(port):
        if port in [80, 443, 8080, 8443]:
            return 0
        elif port in [22, 23]:
            return 1
        elif port == 53:
            return 2
        elif port in [20, 21]:
            return 3
        elif port in [25, 587]:
            return 4
        elif port in [3306, 5432, 27017]:
            return 5
        elif port < 1024:
            return 6
        else:
            return 7

def group_src_port(port):
        if port < 1024:
            return 0
        elif port < 49152:
            return 1
        else:
            return 2

# usecols = ["Label", "Init Bwd Win Byts", "Init Fwd Win Byts", "Protocol", "Dst Port", "Src Port"]
# df = pd.read_csv("./data/final_dataset.csv", usecols=usecols)
# print("Dataframe has been read")

# df_processed = df.copy()
# df_processed['Dst Port Group'] = df['Dst Port'].apply(group_dst_port)
# df_processed['Src Port Group'] = df['Src Port'].apply(group_src_port)
# df_processed = df_processed.drop(['Dst Port', 'Src Port'], axis=1)

# df_goal = df_processed['Label'].apply(sort_label)
# df_processed = df_processed.drop(['Label'], axis=1)

# X_train, X_valid, y_train, y_valid = train_test_split(df_processed, df_goal, random_state=1)

# my_model = RandomForestClassifier(random_state=1, n_jobs=6, n_estimators=50, max_depth=3, min_samples_split=50)
# my_model = LogisticRegression(random_state=1, n_jobs=6)
# my_model = GradientBoostingClassifier(random_state=1, n_jobs=6, n_estimators=100, min_samples_split=50)
# my_model.fit(X_train, y_train)
# print(X_train.columns)
# predictions = my_model.predict(X_valid)
# print("Average_precision_score: " + str(average_precision_score(y_valid, predictions)))
# joblib.dump(my_model, 'my_sklearn_model.pkl')
# loaded_object = joblib.load('my_sklearn_model.pkl')
# print(loaded_object)
# print(f" Average preсision: {average_precision_score(y_valid, loaded_object.predict(X_valid))}")

import pandas as pd
import numpy as np
import joblib
data = pd.read_csv(r'C:\Users\kvsud\OneDrive\Desktop\ML\SWE model\train_updated.csv');
data = data.dropna()
x = data.drop(['TenYearCHD'],axis=1)
y = data['TenYearCHD']
from sklearn.model_selection import train_test_split
x_train,x_test,y_train,y_test = train_test_split(x,y)
from sklearn.linear_model import LogisticRegression
SWE = LogisticRegression(fit_intercept=True, max_iter=10000)
SWE.fit(x_train, y_train)
print(SWE.score(x_test,y_test))
joblib.dump(SWE, 'SWE.pkl')
def predict_swe(input_data, model_path='SWE.pkl'):
    # Load the saved model
    model = joblib.load(model_path)
    # Convert input to numpy array and reshape if necessary
    input_data = np.array(input_data).reshape(1, -1)
    # Make prediction
    prediction = model.predict(input_data)
    probability = model.predict_proba(input_data)[0][1]
    return probability
print(predict_swe([1,36,4,1,0,0,0,0,1,0,212,168,98,29.77,72.0,75.0]))
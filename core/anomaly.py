# core/anomaly.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib # For saving/loading the model
import numpy as np
import os

MODEL_FILENAME = "anomaly_detector_model.joblib"
SCALER_FILENAME = "anomaly_scaler.joblib"
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data") # Assumes data folder is one level up from core
MODEL_PATH = os.path.join(DATA_DIR, MODEL_FILENAME)
SCALER_PATH = os.path.join(DATA_DIR, SCALER_FILENAME)

class AnomalyDetector:
    def __init__(self, contamination="auto"):
        """
        Initialize the Anomaly Detector.
        contamination: The proportion of outliers in the data set. 
                       Can be float, or "auto".
        """
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        # Lista de features suportadas pelo modelo - deve corresponder aos dados de treinamento
        self.supported_features = [
            "message_length", "time_interval", "message_count_window",
            "payload_entropy", "response_time", "decryption_errors", 
            "signature_errors", "replay_flags", "handshake_failures",
            "message_type_variance", "session_duration", "sequential_errors"
        ]

    def _extract_features(self, network_event):
        """
        Extracts features from a network event dictionary.
        A network_event could be a dictionary representing a single communication event or a summary.
        
        Args:
            network_event (dict or list/array): The event data.
                                                If dict, extracts features according to self.supported_features.
                                                If list/array, assumed to be numerical features.
        Returns:
            np.array: A numpy array of features.
        """
        # Para retrocompatibilidade com instâncias antigas que usam apenas 3 features
        legacy_features = ["message_length", "time_interval", "message_count_window"]

        if isinstance(network_event, dict):
            # Verifica se as features avançadas estão presentes
            has_advanced_features = any(f in network_event for f in self.supported_features if f not in legacy_features)
            
            if has_advanced_features:
                # Extrai todas as features suportadas
                features = []
                for feature_name in self.supported_features:
                    # Usa 0 como valor padrão se a feature não estiver presente
                    features.append(network_event.get(feature_name, 0))
            else:
                # Retrocompatibilidade: apenas as 3 features originais
                features = [
                    network_event.get("message_length", 0),
                    network_event.get("time_interval", 0),
                    network_event.get("message_count_window", 0)
                ]
            
            return np.array(features).reshape(1, -1)
        elif isinstance(network_event, (list, np.ndarray)):
            # Se for passada uma lista/array, assume que já estão na ordem correta
            return np.array(network_event).reshape(1, -1)
        else:
            raise ValueError("network_event must be a dict, list, or numpy array")

    def train(self, data_df):
        """
        Trains the Isolation Forest model.
        Args:
            data_df (pd.DataFrame): DataFrame containing features for training.
                                    It is assumed that this data primarily represents normal traffic.
        """
        if data_df.empty:
            print("Training data is empty. Cannot train model.")
            return

        # Verifica quais features do DataFrame correspondem às suportadas
        available_features = [col for col in data_df.columns if col in self.supported_features]
        print(f"Training with features: {available_features}")

        # Usa apenas as features disponíveis que são suportadas
        X = data_df[available_features].values
        
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        print(f"Training Isolation Forest model with {len(X_scaled)} samples...")
        self.model.fit(X_scaled)
        self.is_trained = True
        print("Model training complete.")
        
        # Salva a lista de features utilizadas para futuras predições
        self.supported_features = available_features
        self.save_model()

    def predict(self, network_event):
        """
        Predicts if a network event is an anomaly.
        Args:
            network_event (dict or list/array): A single network event to classify.
        Returns:
            int: 1 for normal, -1 for anomaly. Returns 0 if not trained or error.
        """
        if not self.is_trained:
            print("Model is not trained yet. Please train or load a model first.")
            # Attempt to load model if not trained
            if not self.load_model():
                return 0 # Still not trained

        try:
            features = self._extract_features(network_event)
            
            # Garante que o número de features corresponde ao esperado pelo scaler/modelo
            expected_features = len(self.supported_features)
            actual_features = features.shape[1]
            
            if actual_features != expected_features:
                print(f"Warning: Feature count mismatch. Expected {expected_features}, got {actual_features}.")
                # Adapta o tamanho se possível
                if isinstance(network_event, dict):
                    # Reconstrói o vetor usando apenas as features suportadas
                    features = np.array([network_event.get(f, 0) for f in self.supported_features]).reshape(1, -1)
                else:
                    # Se for array/lista, preenche com zeros ou trunca
                    if actual_features < expected_features:
                        padding = np.zeros((1, expected_features - actual_features))
                        features = np.hstack([features, padding])
                    else:
                        features = features[:, :expected_features]
            
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)
            return int(prediction[0]) # 1 for inlier (normal), -1 for outlier (anomaly)
        except Exception as e:
            print(f"Error during prediction: {e}")
            return 0

    def get_anomaly_score(self, network_event):
        """
        Gets the anomaly score for a network event.
        Lower scores are more anomalous.
        Args:
            network_event (dict or list/array): A single network event.
        Returns:
            float: The anomaly score. Returns 0.0 if not trained or error.
        """
        if not self.is_trained:
            print("Model is not trained yet. Please train or load a model first.")
            if not self.load_model():
                return 0.0
        
        try:
            features = self._extract_features(network_event)
            
            # Garante que o número de features corresponde ao esperado pelo scaler/modelo
            expected_features = len(self.supported_features)
            actual_features = features.shape[1]
            
            if actual_features != expected_features:
                print(f"Warning: Feature count mismatch. Expected {expected_features}, got {actual_features}.")
                # Adapta o tamanho se possível
                if isinstance(network_event, dict):
                    # Reconstrói o vetor usando apenas as features suportadas
                    features = np.array([network_event.get(f, 0) for f in self.supported_features]).reshape(1, -1)
                else:
                    # Se for array/lista, preenche com zeros ou trunca
                    if actual_features < expected_features:
                        padding = np.zeros((1, expected_features - actual_features))
                        features = np.hstack([features, padding])
                    else:
                        features = features[:, :expected_features]
                        
            features_scaled = self.scaler.transform(features)
            # decision_function returns the anomaly score of X of the base classifiers.
            # Negative scores are anomalies, positive are normal. Closer to 0 is less certain.
            score = self.model.decision_function(features_scaled)
            return float(score[0])
        except Exception as e:
            print(f"Error calculating anomaly score: {e}")
            return 0.0

    def save_model(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        """Saves the trained model and scaler to disk."""
        if not self.is_trained:
            print("Model is not trained. Nothing to save.")
            return
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            # Salva também a lista de features suportadas
            model_data = {
                'model': self.model,
                'supported_features': self.supported_features
            }
            
            joblib.dump(model_data, model_path)
            joblib.dump(self.scaler, scaler_path)
            print(f"Model saved to {model_path}")
            print(f"Scaler saved to {scaler_path}")
        except Exception as e:
            print(f"Error saving model: {e}")

    def load_model(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        """Loads a trained model and scaler from disk."""
        try:
            if not os.path.exists(model_path) or not os.path.exists(scaler_path):
                print(f"Model or scaler file not found at specified paths.")
                return False
                
            # Carrega o modelo e lista de features
            model_data = joblib.load(model_path)
            
            # Compatibilidade com modelos salvos no formato antigo
            if isinstance(model_data, dict) and 'model' in model_data:
                self.model = model_data['model']
                self.supported_features = model_data.get('supported_features', 
                                                        ["message_length", "time_interval", "message_count_window"])
            else:
                # Formato antigo: apenas o modelo foi salvo
                self.model = model_data
                self.supported_features = ["message_length", "time_interval", "message_count_window"]
                
            self.scaler = joblib.load(scaler_path)
            self.is_trained = True
            print(f"Model loaded from {model_path}")
            print(f"Scaler loaded from {scaler_path}")
            print(f"Supported features: {self.supported_features}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            self.is_trained = False
            return False

# Example usage (primarily for testing the class structure)
if __name__ == '__main__':
    # This part would typically use a separate script to generate training_data.csv
    # For now, let's create a dummy DataFrame for testing the class methods.
    print("Testing AnomalyDetector class...")
    
    # Create dummy data for training with extended features
    # Features básicas: message_length, time_interval, message_count_window
    # Features avançadas: payload_entropy, response_time, decryption_errors, 
    #                     signature_errors, replay_flags, handshake_failures,
    #                     message_type_variance, session_duration, sequential_errors
    
    # Gera dados normais
    n_samples = 100
    normal_data = np.zeros((n_samples, 12))
    
    # Features básicas
    normal_data[:,0] = np.random.rand(n_samples) * 1000  # message_length
    normal_data[:,1] = np.random.normal(loc=1.0, scale=0.5, size=n_samples)  # time_interval
    normal_data[:,2] = np.random.randint(1, 5, size=n_samples)  # message_count_window
    
    # Features avançadas para dados normais
    normal_data[:,3] = np.random.uniform(3.8, 5.2, size=n_samples)  # payload_entropy
    normal_data[:,4] = np.random.uniform(0.1, 0.8, size=n_samples)  # response_time
    normal_data[:,5] = np.zeros(n_samples)  # decryption_errors
    normal_data[:,6] = np.zeros(n_samples)  # signature_errors
    normal_data[:,7] = np.zeros(n_samples)  # replay_flags
    normal_data[:,8] = np.zeros(n_samples)  # handshake_failures
    normal_data[:,9] = np.random.uniform(0.6, 1.0, size=n_samples)  # message_type_variance
    normal_data[:,10] = np.random.uniform(30, 1800, size=n_samples)  # session_duration
    normal_data[:,11] = np.zeros(n_samples)  # sequential_errors

    # Cria DataFrame
    columns = [
        "message_length", "time_interval", "message_count_window",
        "payload_entropy", "response_time", "decryption_errors", 
        "signature_errors", "replay_flags", "handshake_failures",
        "message_type_variance", "session_duration", "sequential_errors"
    ]
    training_features = pd.DataFrame(normal_data, columns=columns)

    detector = AnomalyDetector(contamination=0.05) # Expect 5% anomalies in training if it had them
    
    # Test training
    print("\nTraining model with dummy data...")
    detector.train(training_features)
    assert detector.is_trained, "Model should be marked as trained."

    # Test prediction with dictionary input (new format)
    print("\nTesting predictions with dictionary input...")
    normal_event = {
        "message_length": 200,
        "time_interval": 1.5,
        "message_count_window": 3,
        "payload_entropy": 4.5,
        "response_time": 0.3,
        "decryption_errors": 0,
        "signature_errors": 0,
        "replay_flags": 0,
        "handshake_failures": 0,
        "message_type_variance": 0.8,
        "session_duration": 300,
        "sequential_errors": 0
    }
    
    prediction_normal = detector.predict(normal_event)
    score_normal = detector.get_anomaly_score(normal_event)
    print(f"Prediction for normal event: {prediction_normal} (Score: {score_normal:.4f})")
    assert prediction_normal == 1, "Normal event misclassified."

    # Test prediction with anomalous event
    anomalous_event = {
        "message_length": 100,
        "time_interval": 0.01,
        "message_count_window": 60,
        "payload_entropy": 7.8,
        "response_time": 5.0,
        "decryption_errors": 2,
        "signature_errors": 3,
        "replay_flags": 1,
        "handshake_failures": 1,
        "message_type_variance": 0.1,
        "session_duration": 10,
        "sequential_errors": 2
    }
    
    prediction_anomaly = detector.predict(anomalous_event)
    score_anomaly = detector.get_anomaly_score(anomalous_event)
    print(f"Prediction for anomalous event: {prediction_anomaly} (Score: {score_anomaly:.4f})")
    assert prediction_anomaly == -1, "Anomalous event misclassified as normal."

    # Test retrocompatibilidade com array simples (formato antigo)
    print("\nTesting backwards compatibility with array input...")
    legacy_normal = [200, 1.5, 3]
    legacy_prediction = detector.predict(legacy_normal)
    legacy_score = detector.get_anomaly_score(legacy_normal)
    print(f"Prediction for legacy normal array: {legacy_prediction} (Score: {legacy_score:.4f})")

    # Test saving and loading
    print("\nTesting model saving and loading...")
    temp_model_path = os.path.join(DATA_DIR, "temp_model.joblib")
    temp_scaler_path = os.path.join(DATA_DIR, "temp_scaler.joblib")
    detector.save_model(temp_model_path, temp_scaler_path)
    assert os.path.exists(temp_model_path), "Model file not saved."
    assert os.path.exists(temp_scaler_path), "Scaler file not saved."

    new_detector = AnomalyDetector()
    assert not new_detector.is_trained, "New detector should not be trained initially."
    loaded_successfully = new_detector.load_model(temp_model_path, temp_scaler_path)
    assert loaded_successfully, "Failed to load model."
    assert new_detector.is_trained, "Loaded model should be marked as trained."

    # Test prediction with loaded model
    prediction_loaded = new_detector.predict(anomalous_event)
    score_loaded = new_detector.get_anomaly_score(anomalous_event)
    print(f"Prediction with loaded model: {prediction_loaded} (Score: {score_loaded:.4f})")
    assert prediction_loaded == -1, "Anomalous event misclassified by loaded model."

    # Clean up temporary files
    if os.path.exists(temp_model_path): os.remove(temp_model_path)
    if os.path.exists(temp_scaler_path): os.remove(temp_scaler_path)
    print("\nAnomalyDetector class basic tests completed.")


# Phishing URL Detection System

A web-based application built with Python Flask that helps users detect phishing URLs using heuristic analysis and machine learning. The system analyzes URLs for suspicious patterns, domain validity, SSL certificates, and other indicators to classify them as legitimate or phishing.

## Features

- **URL Analysis**: Comprehensive heuristic checks including:
  - Domain existence verification
  - SSL certificate validation
  - Domain age checking
  - Suspicious keyword detection
  - IP address usage
  - URL shortener detection
  - Brand impersonation detection
  - Typosquatting detection

- **Machine Learning Model**: Random Forest classifier trained on phishing URL datasets for enhanced detection

- **Risk Scoring**: Provides a risk percentage based on detected suspicious factors

- **Web Interface**: Simple and intuitive HTML/CSS frontend

- **Real-time Detection**: Instant analysis without external API dependencies

## Technologies Used

- **Backend**: Python Flask
- **Machine Learning**: Scikit-learn (Random Forest)
- **Data Processing**: Pandas
- **Frontend**: HTML, CSS
- **Additional Libraries**: dnspython, python-whois

## Installation

### Prerequisites

- Python 3.x
- pip (Python package installer)

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ankush007N/phishing-url-detection-system.git
   cd phishing-url-detection-system
   ```

2. **Install dependencies**:
   ```bash
   pip install flask scikit-learn pandas dnspython python-whois
   ```

3. **Train the model** (if not already trained):
   ```bash
   python model.py
   ```
   This will generate `phishing_model.pkl` using the provided `phishing.csv` dataset.

## Usage

1. **Run the application**:
   ```bash
   python app.py
   ```

2. **Open your browser** and navigate to:
   ```
  [ http://127.0.0.1:5000](https://phishing-url-detection-system-xtsm.onrender.com/)
   ```

3. **Enter a URL** in the input field and click "( https://phishing-url-detection-system-xtsm.onrender.com/ )".

4. **View results**: The system will display whether the URL is legitimate, suspicious, or phishing, along with risk score and reasons for the classification.

## Dataset

The system uses a CSV dataset (`phishing.csv`) containing features extracted from URLs for training the machine learning model. The dataset includes various URL characteristics that help distinguish between legitimate and phishing websites.

## Model Training

The `model.py` script trains a Random Forest classifier on the dataset. Key steps:

- Loads and preprocesses the phishing dataset
- Splits data into training and testing sets (80/20)
- Trains the model and evaluates accuracy
- Saves the trained model as `phishing_model.pkl`

## Project Structure

```
Phishing-URL-Detection-System-main/
├── app.py                 # Main Flask application
├── model.py               # Model training script
├── phishing.csv           # Dataset for training
├── phishing_model.pkl     # Trained model (generated)
├── README.md              # Project documentation
├── Synopsis               # Project synopsis
├── static/
│   └── style.css          # CSS styles
└── templates/
    └── index.html         # HTML template
```

## How It Works

1. **Input Validation**: Checks if the entered URL is valid
2. **Heuristic Analysis**: Applies multiple rules to detect suspicious patterns
3. **Feature Extraction**: Converts URL into numerical features for ML model
4. **Prediction**: Uses both heuristic rules and ML model for final classification
5. **Result Display**: Shows classification, risk score, and detailed reasons

## Limitations

- Rule-based detection may produce false positives
- Limited effectiveness against newly generated phishing URLs
- Requires internet connection for domain checks
- Not a replacement for professional security tools

## Future Enhancements

- Integration with real-time URL reputation APIs
- Database storage for scanned URLs
- Browser extension development
- Advanced machine learning models
- Batch URL analysis

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).

## Disclaimer

This tool is for educational and informational purposes only. It should not be relied upon as the sole method for detecting phishing attempts. Always exercise caution and use multiple security measures.


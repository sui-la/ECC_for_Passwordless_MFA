# ECC for Passwordless MFA

A modern passwordless multi-factor authentication system using Elliptic Curve Cryptography (ECC) for secure user authentication.

## Features

- **Passwordless Authentication**: Secure authentication without traditional passwords
- **ECC-based Security**: Uses Elliptic Curve Cryptography for enhanced security
- **Multi-Factor Authentication**: Multiple authentication factors for increased security
- **Modern Web Interface**: React-based frontend with TypeScript
- **RESTful API**: Flask-based backend with comprehensive API endpoints
- **Docker Support**: Containerized deployment with Docker Compose

## Project Structure

```
ECCforPasswordlessMFA/
├── backend/                 # Flask backend application
│   ├── app.py              # Main Flask application
│   ├── auth/               # Authentication modules
│   ├── crypto/             # ECC cryptographic operations
│   ├── database/           # Database models and operations
│   ├── utils/              # Utility functions
│   └── requirements.txt    # Python dependencies
├── frontend/               # React frontend application
│   ├── src/                # Source code
│   ├── components/         # React components
│   ├── services/           # API and crypto services
│   └── package.json        # Node.js dependencies
└── docker-compose.yml      # Docker orchestration
```

## Prerequisites

- Python 3.8+
- Node.js 16+
- Docker and Docker Compose (optional)

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ECCforPasswordlessMFA.git
   cd ECCforPasswordlessMFA
   ```

2. Start the application:
   ```bash
   docker-compose up --build
   ```

3. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000

### Manual Setup

#### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the Flask application:
   ```bash
   python app.py
   ```

#### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

## API Documentation

The backend provides RESTful API endpoints for:

- User registration and authentication
- ECC key management
- Session management
- Security operations

## Security Features

- **Elliptic Curve Cryptography**: Uses ECDSA and ECDH for secure operations
- **Session Management**: Secure session handling with token-based authentication
- **Input Validation**: Comprehensive input validation and sanitization
- **CORS Protection**: Cross-Origin Resource Sharing protection

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions, please open an issue on GitHub. 
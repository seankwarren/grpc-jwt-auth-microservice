# gRPC Authentication Server

This repository contains a gRPC authentication server implemented in Python, using gRPC for communication and JWT for authentication.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.x
- pip
- virtualenv (optional, but recommended)

### Installing

First, clone the repository to your local machine:

```bash
git clone https://github.com/seankwarren/grpc-jwt-auth-microservice.git
```

Then, navigate to the project directory:

```bash
cd grpc-jwt-auth-microservice
```

Optionally, create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment:

- On Linux/MacOS:

```bash
source .venv/bin/activate
```

- On Windows:

```bash
.venv\Scripts\activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

### Running the Server

To start the gRPC authentication server, run:

```bash
python src/server.py
```

### Running Tests

To run the tests, execute:

```bash
pytest src/test.py -v
```

### Configuration: Environment Variables

Below are the environment variables used by the server:

- `ACCESS_TOKEN_LIFETIME`: Specifies the lifetime of access tokens in minutes. Default is 30 minutes.
- `REFRESH_TOKEN_LIFETIME`: Specifies the lifetime of refresh tokens in days. Default is 30 days.
- `JWT_SECRET`: Specifies the secret key used to sign JWT tokens.
- `SERVER_PORT`: Specifies the port on which the gRPC server will listen. Default is 50051.


### Folder Structure

The project's folder structure is as follows:

```bash
.
├── build_protos.sh         # Script to generate gRPC code from proto files
├── requirements.txt        # Python dependencies
└── src                     # Source files
    ├── jwt_utils.py        # JWT utility functions
    ├── protos              # Proto files and generated gRPC code
    │   ├── auth_service.proto
    │   ├── auth_service_pb2.py
    │   ├── auth_service_pb2.pyi
    │   └── auth_service_pb2_grpc.py
    ├── server.py           # gRPC server implementation
    ├── status.py           # Status message definitions
    └── test.py             # Tests for the gRPC service
```

### Authors

Sean Warren - Initial work

### License

This project is licensed under the MIT License - see the `LICENSE.md` file for details

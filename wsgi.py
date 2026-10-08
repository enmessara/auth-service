"""Production entrypoint:  gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app"""
from auth_service import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

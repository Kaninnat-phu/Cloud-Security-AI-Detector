FROM python:3.11-slim

WORKDIR /app

COPY src/ ./src/
COPY .env.example ./

RUN pip install boto3 anthropic flask scikit-learn numpy aiofiles python-dotenv

EXPOSE 5001

CMD ["python", "src/dashboard.py"]
